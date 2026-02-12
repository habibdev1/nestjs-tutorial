import { Injectable, Logger } from '@nestjs/common';
import { apiResponse } from '@app/common-lib';
import { SignupDto } from './dto/signup.dto';
import { UserSchema } from './schemas/user.schema';
import { EmailLibService } from '@app/email-lib';
import * as bcrypt from 'bcrypt';
import { welcomeTemplate } from '@app/email-lib/templates/welcome.template';
import { LoginDto } from './dto/login.dto';
import { VerifyOtpDto } from './dto/verify-otp.dto';
import { RedisLibService } from '@app/redis-lib';
import { otpLoginTemplate } from '@app/email-lib/templates/otp-login.template';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { v4 as uuidv4 } from 'uuid';
import { accountLockedTemplate } from '@app/email-lib/templates/account-locked.template';

@Injectable()
export class AuthServiceService {
  private readonly logger = new Logger(AuthServiceService.name);

  constructor(
    private readonly mailer: EmailLibService,
    private readonly redis: RedisLibService,
    private readonly jwt: JwtService,
    private readonly config: ConfigService,
  ) {}

  /**
   * Handles user signup:
   *  - Validate tenant connection
   *  - Hash password
   *  - Save user into tenant DB
   *  - Send welcome email (non-blocking)
   *
   * Uses Logger for professional monitoring & error tracking.
   */
  async signup(req: any, dto: SignupDto) {
    try {
      const conn = req.tenantConnection;
      if (!conn) {
        this.logger.warn(
          `❌ Tenant connection missing for signup: ${dto.email}`,
        );
        return apiResponse(
          'Signup failed: Tenant environment is not initialized. Please retry after selecting the correct workspace or tenant.',
          null,
          {
            status: 'error',
            code: 'TENANT_CONNECTION_MISSING',
            details: { email: dto.email },
          },
        );
      }

      const User = conn.model('User', UserSchema);
      const hashed = await bcrypt.hash(dto.password, 10);

      const user = new User({ ...dto, password: hashed });
      const saved = await user.save();

      this.logger.log(
        `✅ New user created: ${saved.username} (${saved.email})`,
      );

      try {
        await this.mailer.sendMail(
          dto.email,
          'Welcome to DARMIST Lab',
          welcomeTemplate,
          { name: dto.name, email: dto.email },
          `Welcome ${dto.name}, your account has been created successfully.`,
        );
        this.logger.log(`📧 Welcome email sent to ${dto.email}`);
      } catch (emailErr) {
        this.logger.error(
          `📧 Failed to send welcome email to ${dto.email}`,
          emailErr.stack,
        );
      }

      return apiResponse(
        'Your account has been created successfully. You can now log in to your workspace.',
        {
          id: saved._id,
          name: saved.name,
          username: saved.username,
          email: saved.email,
          role: saved.role,
        },
        {
          status: 'success',
          code: 'USER_CREATED',
        },
      );
    } catch (err: any) {
      if (err?.code === 11000 && err?.keyValue) {
        const fields = Object.keys(err.keyValue);
        const duplicates = fields.map((f) => `${f} "${err.keyValue[f]}"`);
        this.logger.warn(
          `⚠️ Duplicate signup attempt: ${duplicates.join(', ')}`,
        );
        return apiResponse(
          'Signup failed: Some information already exists in the system. Please use different values.',
          null,
          {
            status: 'error',
            code: 'DUPLICATE_ENTRY',
            message: `Duplicate fields: ${duplicates.join(', ')}`,
          },
        );
      }

      if (err?.name === 'ValidationError') {
        const messages = Object.values(err.errors).map(
          (e: any) => e.message || e,
        );
        this.logger.warn(
          `⚠️ Validation failed for signup: ${messages.join(', ')}`,
        );
        return apiResponse(
          'Signup failed due to invalid or missing information. Please review your inputs.',
          null,
          {
            status: 'error',
            code: 'VALIDATION_FAILED',
            message: messages.join(', '),
          },
        );
      }

      this.logger.error(
        `❌ Unexpected signup error: ${err.message}`,
        err.stack,
      );
      return apiResponse(
        'Signup failed due to a system error. Please try again later.',
        null,
        {
          status: 'error',
          code: 'INTERNAL_ERROR',
          error: err.message || 'Unknown error',
        },
      );
    }
  }

  // ───────────────────────────────
  // LOGIN → Validate credentials & send OTP
  // ───────────────────────────────
  async login(req: any, dto: LoginDto) {
    try {
      const conn = req.tenantConnection;
      if (!conn) {
        this.logger.warn(
          `❌ Tenant connection missing (tenantId=${req.tenantId})`,
        );
        return apiResponse(
          'Login failed: Tenant environment is not initialized. Please retry after selecting the correct workspace.',
          null,
          {
            status: 'error',
            code: 'TENANT_CONNECTION_MISSING',
            details: { tenantId: req.tenantId },
          },
        );
      }

      const User = conn.model('User', UserSchema);
      const user = await User.findOne({
        $or: [
          { username: dto.usernameOrEmailOrMobile },
          { email: dto.usernameOrEmailOrMobile },
          { mobile: dto.usernameOrEmailOrMobile },
        ],
      });

      if (!user) {
        this.logger.warn(
          `❌ Login failed: user not found for ${dto.usernameOrEmailOrMobile} (tenantId=${req.tenantId})`,
        );
        return apiResponse(
          'Invalid credentials. Please check your username, email, or mobile number and try again.',
          null,
          {
            status: 'error',
            code: 'INVALID_CREDENTIALS',
            field: 'usernameOrEmailOrMobile',
          },
        );
      }

      if (user.status === 0) {
        this.logger.warn(`🔒 Locked account tried to login: ${user.email}`);
        return apiResponse(
          'Your account is currently locked. Please check your email for unlock instructions or contact support.',
          null,
          {
            status: 'error',
            code: 'ACCOUNT_LOCKED',
            email: user.email,
          },
        );
      }

      const valid = await bcrypt.compare(dto.password, user.password);
      if (!valid) {
        await this.recordFailedAttempt(
          req.tenantId,
          conn,
          user._id,
          user.email,
          user.name,
        );
        this.logger.warn(`❌ Invalid password for user ${user.email}`);
        return apiResponse(
          'Incorrect password. Please try again or reset your password if forgotten.',
          null,
          {
            status: 'error',
            code: 'INVALID_PASSWORD',
            field: 'password',
          },
        );
      }

      await this.redis.del(`login:fail:${req.tenantId}:${user._id}`);

      const loginId = uuidv4();
      const otp = Math.floor(100000 + Math.random() * 900000).toString();

      await this.redis.set(
        `otp:login:${loginId}`,
        JSON.stringify({ userId: user._id, otp }),
        300,
      );

      try {
        await this.mailer.sendMail(
          user.email,
          'DARMIST Lab Login OTP',
          otpLoginTemplate,
          { name: user.name, otp, year: new Date().getFullYear() },
          `Your DARMIST Lab OTP is ${otp}`,
        );
        this.logger.log(`📧 OTP sent to ${user.email} (loginId=${loginId})`);
      } catch (mailErr) {
        this.logger.error(
          `📧 Failed to send OTP email to ${user.email}`,
          mailErr.stack,
        );
        return apiResponse(
          'We could not send the OTP to your email at this moment. Please try again later.',
          null,
          {
            status: 'error',
            code: 'OTP_SEND_FAILED',
            error: mailErr.message,
          },
        );
      }

      return apiResponse(
        'A verification OTP has been sent to your registered email address. Please check your inbox.',
        {
          loginId,
          channel: 'email',
          maskedEmail: this.maskEmail(user.email),
        },
        {
          status: 'success',
          code: 'OTP_SENT',
        },
      );
    } catch (err: any) {
      this.logger.error(`❌ Unexpected login error`, err.stack || err);
      return apiResponse(
        'Login failed due to a system error. Please try again later.',
        null,
        {
          status: 'error',
          code: 'INTERNAL_ERROR',
          error: err.message || 'Unknown error',
        },
      );
    }
  }

  // ───────────────────────────────
  // VERIFY OTP → Issue tokens + Save session
  // ───────────────────────────────
  async verifyOtp(req: any, dto: VerifyOtpDto) {
    try {
      const conn = req.tenantConnection;
      if (!conn) {
        this.logger.warn(
          `❌ Tenant connection missing (tenantId=${req.tenantId})`,
        );
        return apiResponse(
          'OTP verification failed: Tenant environment not initialized. Please retry.',
          null,
          {
            status: 'error',
            code: 'TENANT_CONNECTION_MISSING',
            details: { tenantId: req.tenantId },
          },
        );
      }

      const data = await this.redis.get(`otp:login:${dto.loginId}`);
      if (!data) {
        this.logger.warn(
          `❌ OTP expired or invalid (loginId=${dto.loginId}, tenantId=${req.tenantId})`,
        );
        return apiResponse(
          'Your OTP has expired or is invalid. Please request a new OTP to continue.',
          null,
          {
            status: 'error',
            code: 'OTP_EXPIRED_OR_INVALID',
            loginId: dto.loginId,
          },
        );
      }

      let parsed: { userId: string; otp: string };
      try {
        parsed = JSON.parse(
          typeof data === 'string' ? data : JSON.stringify(data),
        );
      } catch (err) {
        this.logger.error(
          `❌ Failed to parse OTP data (loginId=${dto.loginId})`,
          err?.stack || '',
        );
        return apiResponse(
          'Verification failed due to corrupted OTP data. Please try again.',
          null,
          {
            status: 'error',
            code: 'OTP_DATA_CORRUPTED',
            loginId: dto.loginId,
          },
        );
      }

      const { userId, otp } = parsed;
      const User = conn.model('User', UserSchema);
      const user = await User.findById(userId);

      if (!user) {
        this.logger.warn(
          `❌ OTP verification failed: user not found (userId=${userId}, tenantId=${req.tenantId})`,
        );
        return apiResponse(
          'User not found. Please reinitiate the login process.',
          null,
          {
            status: 'error',
            code: 'USER_NOT_FOUND',
            userId,
          },
        );
      }

      if (dto.otp !== otp) {
        this.logger.warn(
          `❌ OTP mismatch for user ${user.email} (tenantId=${req.tenantId}, provided=${dto.otp}, expected=${otp})`,
        );
        return apiResponse(
          'Incorrect OTP entered. Please check and try again.',
          null,
          {
            status: 'error',
            code: 'INVALID_OTP',
            field: 'otp',
          },
        );
      }

      await this.redis.del(`otp:login:${dto.loginId}`);

      const sessionId = uuidv4();
      const payload = {
        sub: String(user._id),
        tenantId: req.tenantId,
        username: user.username,
        role: user.role,
        sid: sessionId,
      };

      const accessToken = this.jwt.sign(payload, {
        expiresIn: this.config.get('JWT_EXPIRES_IN', '15m'),
      });
      const refreshToken = this.jwt.sign(payload, {
        expiresIn: this.config.get('JWT_REFRESH_EXPIRES_IN', '7d'),
      });

      const crypto = await import('crypto');
      const refreshHash = crypto
        .createHash('sha256')
        .update(refreshToken)
        .digest('hex');

      const session = {
        sessionId,
        deviceName: req.headers?.['user-agent'] || 'Unknown',
        ip:
          req.headers?.['host'] | req.ip ||
          req.connection?.remoteAddress ||
          'N/A',
        ua: req.headers?.['user-agent'] || 'Unknown',
        refreshHash,
        createdAt: new Date(),
        lastSeen: new Date(),
      };

      await User.updateOne({ _id: user._id }, { $push: { sessions: session } });

      this.logger.log(
        `✅ User ${user.email} logged in successfully (tenantId=${req.tenantId}, sessionId=${sessionId})`,
      );

      return apiResponse(
        'You have successfully logged in to DARMIST Lab.',
        {
          accessToken,
          refreshToken,
          sessionId,
          user: { id: user._id, username: user.username, role: user.role },
        },
        {
          status: 'success',
          code: 'LOGIN_SUCCESS',
        },
      );
    } catch (err: any) {
      this.logger.error(
        `❌ Unexpected error in verifyOtp (tenantId=${req.tenantId}, loginId=${dto.loginId})`,
        err?.stack || err,
      );
      return apiResponse(
        'Login verification failed due to an unexpected system error. Please try again later.',
        null,
        {
          status: 'error',
          code: 'INTERNAL_ERROR',
          error: err.message || 'Unknown error',
        },
      );
    }
  }

  // ───────────────────────────────
  // RECORD FAILED ATTEMPT & LOCK IF LIMIT REACHED
  // ───────────────────────────────
  private async recordFailedAttempt(
    tenantId: string,
    conn: any,
    userId: string,
    email: string,
    name: string,
  ) {
    const maxAttempts = this.config.get<number>('LOGIN_MAX_ATTEMPTS', 7);
    const lockMinutes = this.config.get<number>('LOGIN_LOCK_MINUTES', 60);

    const key = `login:fail:${tenantId}:${userId}`;
    const attempts = (parseInt((await this.redis.get(key)) || '0') || 0) + 1;

    await this.redis.set(key, attempts.toString(), lockMinutes * 60);

    if (attempts >= maxAttempts) {
      // Lock user account
      const User = conn.model('User', UserSchema);
      await User.findByIdAndUpdate(userId, { status: 0 });

      // Generate unlock token
      const unlockToken = uuidv4();
      await this.redis.set(
        `unlock:${unlockToken}`,
        JSON.stringify({ tenantId, userId }),
        86400, // 24h
      );

      const unlockUrl = `${this.config.get<string>('APP_BASE_URL')}/auth/unlock?token=${unlockToken}`;

      // Send unlock email
      await this.mailer.sendMail(
        email,
        'Your DARMIST Lab Account is Locked',
        accountLockedTemplate,
        { name, unlockUrl, year: new Date().getFullYear() },
        `Your account is locked. Unlock here: ${unlockUrl}`,
      );

      this.logger.warn(`🔒 Account locked: ${email}`);
    }
  }

  // ───────────────────────────────
  // UNLOCK ACCOUNT
  // ───────────────────────────────
  async unlock(token: string, conn: any) {
    try {
      const data = await this.redis.get(`unlock:${token}`);
      if (!data) {
        this.logger.warn(`❌ Invalid or expired unlock token used`);
        return apiResponse(
          'The unlock link is invalid or has expired. Please request a new unlock email.',
          null,
          { status: 'error', code: 'INVALID_OR_EXPIRED_TOKEN' },
        );
      }

      const parsed: any = typeof data === 'string' ? JSON.parse(data) : data;
      const { tenantId, userId } = parsed;

      if (!tenantId || !userId) {
        this.logger.error(
          `⚠️ Unlock token data incomplete: ${JSON.stringify(parsed)}`,
        );
        return apiResponse(
          'Unlock request failed due to incomplete token data. Please generate a new unlock link.',
          null,
          { status: 'error', code: 'TOKEN_DATA_INCOMPLETE' },
        );
      }

      const User = conn.model('User', UserSchema);
      const user = await User.findById(userId);
      if (!user) {
        this.logger.warn(
          `⚠️ User not found for unlock token (userId=${userId}, tenant=${tenantId})`,
        );
        return apiResponse(
          'No user account found for the provided unlock link.',
          null,
          { status: 'error', code: 'USER_NOT_FOUND' },
        );
      }

      if (user.status === 1) {
        this.logger.log(
          `ℹ️ User already unlocked (userId=${userId}, tenant=${tenantId})`,
        );
        return apiResponse(
          'Your account is already unlocked. You can log in using your credentials.',
          { userId, tenantId },
          { status: 'success', code: 'ACCOUNT_ALREADY_UNLOCKED' },
        );
      }

      await User.findByIdAndUpdate(userId, { status: 1 });
      await this.redis.del(`unlock:${token}`);

      this.logger.log(
        `✅ Account unlocked successfully: user=${userId}, tenant=${tenantId}`,
      );
      return apiResponse(
        'Your account has been unlocked successfully. You may now log in again.',
        { userId, tenantId },
        { status: 'success', code: 'ACCOUNT_UNLOCKED' },
      );
    } catch (err: any) {
      this.logger.error(
        `❌ Unexpected error during account unlock`,
        err.stack || err,
      );
      return apiResponse(
        'Account unlock failed due to a system error. Please try again later.',
        null,
        {
          status: 'error',
          code: 'INTERNAL_ERROR',
          error: err.message || 'Unknown error',
        },
      );
    }
  }

  // ───────────────────────────────
  // LIST SESSIONS
  // ───────────────────────────────
  async listSessions(req: any) {
    try {
      const conn = req.tenantConnection;
      if (!conn) {
        this.logger.warn(
          `❌ Tenant connection missing (tenantId=${req.tenantId})`,
        );
        return apiResponse(
          'Unable to fetch sessions because tenant environment is not initialized.',
          null,
          {
            status: 'error',
            code: 'TENANT_CONNECTION_MISSING',
            details: { tenantId: req.tenantId },
          },
        );
      }

      // console.log(req);

      const userId = req.user?.sub;
      if (!userId) {
        this.logger.warn(
          `⚠️ Missing user ID in session request (tenantId=${req.tenantId})`,
        );
        return apiResponse(
          'Session request failed: user identity missing in the request payload.',
          null,
          { status: 'error', code: 'USER_ID_MISSING' },
        );
      }

      const User = conn.model('User', UserSchema);
      const user = await User.findById(userId, { sessions: 1 }).lean();

      if (!user) {
        this.logger.warn(
          `⚠️ User not found (userId=${userId}, tenantId=${req.tenantId})`,
        );
        return apiResponse('User not found for the current tenant.', null, {
          status: 'error',
          code: 'USER_NOT_FOUND',
        });
      }

      const sessions = user.sessions || [];
      this.logger.log(
        `📋 Retrieved ${sessions.length} sessions for user=${userId}`,
      );
      return apiResponse(
        'Active login sessions retrieved successfully.',
        sessions,
        { status: 'success', code: 'SESSIONS_RETRIEVED' },
      );
    } catch (err: any) {
      this.logger.error(
        `❌ Unexpected error fetching sessions`,
        err.stack || err,
      );
      return apiResponse(
        'Failed to retrieve sessions due to a system error. Please try again later.',
        null,
        {
          status: 'error',
          code: 'INTERNAL_ERROR',
          error: err.message || 'Unknown error',
        },
      );
    }
  }

  // ───────────────────────────────
  // LOGOUT SINGLE SESSION
  // ───────────────────────────────
  async logoutSession(req: any, sessionId: string) {
    try {
      const conn = req.tenantConnection;
      if (!conn) {
        this.logger.warn(
          `❌ Tenant connection missing (tenantId=${req.tenantId})`,
        );
        return apiResponse(
          'Logout failed because tenant environment is not initialized.',
          null,
          {
            status: 'error',
            code: 'TENANT_CONNECTION_MISSING',
            details: { tenantId: req.tenantId },
          },
        );
      }

      const userId = req.user?.sub;
      if (!userId) {
        this.logger.warn(
          `⚠️ Missing user ID during logout (tenantId=${req.tenantId})`,
        );
        return apiResponse('Logout request missing user identity.', null, {
          status: 'error',
          code: 'USER_ID_MISSING',
        });
      }

      const User = conn.model('User', UserSchema);
      const user = await User.findById(userId);
      if (!user) {
        this.logger.warn(
          `⚠️ User not found (userId=${userId}, tenantId=${req.tenantId})`,
        );
        return apiResponse('User not found.', null, {
          status: 'error',
          code: 'USER_NOT_FOUND',
        });
      }

      const existingSession = user.sessions?.find(
        (s: any) => s.sessionId === sessionId,
      );
      if (!existingSession) {
        this.logger.warn(
          `⚠️ Session not found (sessionId=${sessionId}, userId=${userId})`,
        );
        return apiResponse('Session not found or already logged out.', null, {
          status: 'error',
          code: 'SESSION_NOT_FOUND',
          sessionId,
        });
      }

      await User.updateOne(
        { _id: userId },
        { $pull: { sessions: { sessionId } } },
      );
      this.logger.log(
        `✅ Session revoked (user=${userId}, session=${sessionId})`,
      );

      return apiResponse(
        'Session has been revoked successfully.',
        { sessionId },
        { status: 'success', code: 'SESSION_REVOKED' },
      );
    } catch (err: any) {
      this.logger.error(`❌ Unexpected error during logout`, err.stack || err);
      return apiResponse(
        'Logout failed due to a system error. Please try again later.',
        null,
        {
          status: 'error',
          code: 'INTERNAL_ERROR',
          error: err.message || 'Unknown error',
        },
      );
    }
  }

  // ───────────────────────────────
  // LOGOUT ALL SESSIONS
  // ───────────────────────────────
  async logoutAll(req: any) {
    try {
      const conn = req.tenantConnection;
      if (!conn) {
        this.logger.warn(
          `❌ Tenant connection missing (tenantId=${req.tenantId})`,
        );
        return apiResponse(
          'Unable to perform logout-all because tenant environment is not initialized.',
          null,
          {
            status: 'error',
            code: 'TENANT_CONNECTION_MISSING',
            details: { tenantId: req.tenantId },
          },
        );
      }

      const userId = req.user?.sub;
      if (!userId) {
        this.logger.warn(
          `⚠️ Missing user ID during logout-all (tenantId=${req.tenantId})`,
        );
        return apiResponse('Logout-all request missing user identity.', null, {
          status: 'error',
          code: 'USER_ID_MISSING',
        });
      }

      const User = conn.model('User', UserSchema);
      const user = await User.findById(userId);
      if (!user) {
        this.logger.warn(`⚠️ User not found for logout-all (userId=${userId})`);
        return apiResponse('User not found.', null, {
          status: 'error',
          code: 'USER_NOT_FOUND',
        });
      }

      const activeSessions = user.sessions?.length || 0;
      await User.updateOne({ _id: userId }, { $set: { sessions: [] } });

      this.logger.log(`✅ All sessions cleared for user=${userId}`);
      return apiResponse(
        'All sessions have been revoked successfully.',
        { revokedCount: activeSessions },
        { status: 'success', code: 'ALL_SESSIONS_REVOKED' },
      );
    } catch (err: any) {
      this.logger.error(
        `❌ Unexpected error during logout-all`,
        err.stack || err,
      );
      return apiResponse(
        'Logout-all failed due to a system error. Please try again later.',
        null,
        {
          status: 'error',
          code: 'INTERNAL_ERROR',
          error: err.message || 'Unknown error',
        },
      );
    }
  }

  // ───────────────────────────────
  // REFRESH TOKENS
  // ───────────────────────────────
  async refresh(req: any, refreshToken: string) {
    try {
      const conn = req.tenantConnection;
      if (!conn) {
        this.logger.warn(
          `❌ Tenant connection missing (tenantId=${req.tenantId})`,
        );
        return apiResponse(
          'Token refresh failed because tenant environment is not initialized.',
          null,
          {
            status: 'error',
            code: 'TENANT_CONNECTION_MISSING',
            details: { tenantId: req.tenantId },
          },
        );
      }

      let payload: any;
      try {
        payload = this.jwt.verify(refreshToken);
      } catch {
        this.logger.warn(`⚠️ Invalid or expired refresh token`);
        return apiResponse(
          'The provided refresh token is invalid or has expired. Please log in again.',
          null,
          { status: 'error', code: 'INVALID_REFRESH_TOKEN' },
        );
      }

      const { sub: userId, sid } = payload;
      const User = conn.model('User', UserSchema);
      const user = await User.findById(userId);
      if (!user) {
        this.logger.warn(`⚠️ User not found (userId=${userId})`);
        return apiResponse('User not found.', null, {
          status: 'error',
          code: 'USER_NOT_FOUND',
        });
      }

      const session = user.sessions?.find((s: any) => s.sessionId === sid);
      if (!session) {
        this.logger.warn(`⚠️ Session not found (sessionId=${sid})`);
        return apiResponse(
          'Session not found or expired. Please log in again.',
          null,
          { status: 'error', code: 'SESSION_NOT_FOUND', sessionId: sid },
        );
      }

      const crypto = await import('crypto');
      const hash = crypto
        .createHash('sha256')
        .update(refreshToken)
        .digest('hex');
      if (hash !== session.refreshHash) {
        this.logger.warn(
          `⚠️ Refresh token mismatch (user=${userId}, session=${sid})`,
        );
        return apiResponse(
          'Invalid refresh token. Please log in again to continue.',
          null,
          { status: 'error', code: 'INVALID_REFRESH_HASH' },
        );
      }

      const newPayload = {
        sub: userId,
        tenantId: req.tenantId,
        role: user.role,
        sid,
      };

      const accessToken = this.jwt.sign(newPayload, {
        expiresIn: this.config.get('JWT_EXPIRES_IN', '15m'),
      });
      const newRefresh = this.jwt.sign(newPayload, {
        expiresIn: this.config.get('JWT_REFRESH_EXPIRES_IN', '7d'),
      });

      const newHash = crypto
        .createHash('sha256')
        .update(newRefresh)
        .digest('hex');

      await User.updateOne(
        { _id: user._id, 'sessions.sessionId': sid },
        {
          $set: {
            'sessions.$.refreshHash': newHash,
            'sessions.$.lastSeen': new Date(),
          },
        },
      );

      this.logger.log(`🔄 Tokens refreshed successfully (user=${userId})`);
      return apiResponse(
        'Access and refresh tokens have been renewed successfully.',
        { accessToken, refreshToken: newRefresh },
        { status: 'success', code: 'TOKENS_REFRESHED' },
      );
    } catch (err: any) {
      this.logger.error(
        `❌ Unexpected error during token refresh`,
        err.stack || err,
      );
      return apiResponse(
        'Token refresh failed due to a system error. Please try again later.',
        null,
        {
          status: 'error',
          code: 'INTERNAL_ERROR',
          error: err.message || 'Unknown error',
        },
      );
    }
  }

  // ───────────────────────────────
  // Validate a session
  // ───────────────────────────────
  async validateSession(req: any) {
    try {
      // ============================================================
      // 1️⃣ Extract Token (from Header, Cookie, or Custom Header)
      // ============================================================
      const extractToken = () => {
        const auth = req.headers?.authorization || req.headers?.Authorization;
        if (auth && typeof auth === 'string') {
          const [scheme, value] = auth.trim().split(/\s+/);
          if (/^Bearer$/i.test(scheme) && value) return value;
          if (!/\s/.test(auth)) return auth;
        }

        const xToken = req.headers?.['x-access-token'];
        if (xToken && typeof xToken === 'string') return xToken.trim();

        const cookies = req.cookies || {};
        if (cookies.AccessToken) return String(cookies.AccessToken);
        if (cookies.authorization) return String(cookies.authorization);

        return null;
      };

      const token = extractToken();
      if (!token) {
        return apiResponse('Access token not provided.', null, {
          status: 'error',
          code: 'ACCESS_TOKEN_MISSING',
        });
      }

      // ============================================================
      // 2️⃣ Verify JWT Token
      // ============================================================
      let payload: any;
      try {
        payload = this.jwt.verify(token);
      } catch (err) {
        this.logger.warn(`⚠️ Invalid or expired access token`);
        return apiResponse('Invalid or expired access token.', null, {
          status: 'error',
          code: 'INVALID_ACCESS_TOKEN',
        });
      }

      const { sub: userId, tenantId, sid } = payload;
      if (!userId || !tenantId) {
        return apiResponse('Malformed token payload.', null, {
          status: 'error',
          code: 'MALFORMED_TOKEN',
          details: { payload },
        });
      }

      // ============================================================
      // 3️⃣ Ensure Tenant Connection Exists
      // ============================================================
      const conn = req.tenantConnection;
      if (!conn) {
        this.logger.warn(`❌ Tenant connection missing (tenantId=${tenantId})`);
        return apiResponse('Tenant environment not initialized.', null, {
          status: 'error',
          code: 'TENANT_CONNECTION_MISSING',
          details: { tenantId },
        });
      }

      // ============================================================
      // 4️⃣ Find User and Validate Session
      // ============================================================
      const User = conn.model('User', UserSchema);
      const user = await User.findById(userId).select(
        '-password -sessions.refreshHash',
      );

      if (!user) {
        this.logger.warn(`⚠️ User not found (userId=${userId})`);
        return apiResponse('User not found.', null, {
          status: 'error',
          code: 'USER_NOT_FOUND',
        });
      }

      if (sid) {
        const activeSession = user.sessions?.find(
          (s: any) => s.sessionId === sid,
        );
        if (!activeSession) {
          this.logger.warn(`⚠️ Session not found or expired (sid=${sid})`);
          return apiResponse('Session not found or expired.', null, {
            status: 'error',
            code: 'SESSION_NOT_FOUND',
            sessionId: sid,
          });
        }

        // Optionally check if session is marked "loggedOut" or "disabled"
        if (
          activeSession.loggedOutAt ||
          activeSession.status === 'LOGGED_OUT'
        ) {
          this.logger.warn(`⚠️ Session already logged out (sid=${sid})`);
          return apiResponse('Session already logged out.', null, {
            status: 'error',
            code: 'SESSION_LOGGED_OUT',
            sessionId: sid,
          });
        }
      }

      // ============================================================
      // 5️⃣ Construct Safe User Object
      // ============================================================
      const safeUser = {
        id: user._id,
        username: user.username,
        name: user.name,
        email: user.email,
        mobile: user.mobile,
        role: user.role,
        sessionId: sid ?? null,
        lastLoginAt: user.lastLoginAt,
        createdAt: user.createdAt,
        updatedAt: user.updatedAt,
      };

      this.logger.log(
        `✅ Token validated (user=${userId}, tenant=${tenantId})`,
      );
      return apiResponse('Token validated successfully.', safeUser, {
        status: 'success',
        code: 'ACCESS_TOKEN_VALID',
      });
    } catch (err: any) {
      this.logger.error('❌ Error validating access token', err.stack || err);
      return apiResponse('Failed to validate access token.', null, {
        status: 'error',
        code: 'INTERNAL_ERROR',
        error: err.message || 'Unknown error',
      });
    }
  }

  // ───────────────────────────────
  // Get current user details from access token
  // ───────────────────────────────
  async getCurrentUserFromAccessToken(req: any) {
    try {
      // -------------------- 1. Extract access token --------------------
      const token = this.extractAccessToken(req);
      if (!token) {
        return apiResponse('Access token not provided.', null, {
          status: 'error',
          code: 'ACCESS_TOKEN_MISSING',
        });
      }

      // -------------------- 2. Verify token --------------------
      let payload: any;
      try {
        payload = this.jwt.verify(token);
      } catch (e) {
        return apiResponse('Invalid or expired access token.', null, {
          status: 'error',
          code: 'INVALID_ACCESS_TOKEN',
        });
      }

      const { sub: userId, tenantId } = payload;
      if (!userId || !tenantId) {
        return apiResponse(
          'Invalid token payload: missing userId or tenantId.',
          null,
          { status: 'error', code: 'MALFORMED_TOKEN' },
        );
      }

      // -------------------- 3. Resolve tenant connection --------------------
      const conn = req.tenantConnection;
      if (!conn) {
        return apiResponse('Tenant environment is not initialized.', null, {
          status: 'error',
          code: 'TENANT_CONNECTION_MISSING',
          details: { tenantId },
        });
      }

      // -------------------- 4. Load user from DB --------------------
      const User = conn.model('User', UserSchema);
      const user = await User.findById(userId).select(
        '-password -sessions.refreshHash',
      );
      if (!user) {
        return apiResponse('User not found.', null, {
          status: 'error',
          code: 'USER_NOT_FOUND',
          userId,
        });
      }

      // Optional: if token includes a sessionId, validate it exists
      if (payload.sid) {
        const sessionExists = user.sessions?.some(
          (s: any) => s.sessionId === payload.sid,
        );
        if (!sessionExists) {
          return apiResponse('Session not found or expired.', null, {
            status: 'error',
            code: 'SESSION_NOT_FOUND',
            sessionId: payload.sid,
          });
        }
      }

      // -------------------- 5. Prepare safe response object --------------------
      const safeUser = {
        id: user._id,
        username: user.username,
        name: user.name,
        email: user.email,
        mobile: user.mobile,
        role: user.role,
        sessionId: payload.sid ?? null,
        lastLoginAt: user.lastLoginAt,
        createdAt: user.createdAt,
        updatedAt: user.updatedAt,
      };

      return apiResponse('Current user retrieved successfully.', safeUser, {
        status: 'success',
        code: 'CURRENT_USER_OK',
      });
    } catch (err: any) {
      this.logger.error(
        '❌ Error in getCurrentUserFromAccessToken',
        err.stack || err,
      );
      return apiResponse('Failed to retrieve current user from token.', null, {
        status: 'error',
        code: 'INTERNAL_ERROR',
        error: err.message,
      });
    }
  }

  // ───────────────────────────────
  // Change User Role
  // ───────────────────────────────
  async changeUserRole(
    req: any,
    { userId, newRole }: { userId: string; newRole: string },
  ) {
    try {
      const conn = req.tenantConnection;
      if (!conn) {
        this.logger.warn(
          `❌ Tenant connection missing (tenantId=${req.tenantId})`,
        );
        return apiResponse(
          'Role update failed because tenant environment is not initialized.',
          null,
          {
            status: 'error',
            code: 'TENANT_CONNECTION_MISSING',
            details: { tenantId: req.tenantId },
          },
        );
      }

      const User = conn.model('User', UserSchema);
      const user = await User.findById(userId);

      if (!user) {
        this.logger.warn(
          `❌ Role change failed: user not found (userId=${userId}, tenantId=${req.tenantId})`,
        );
        return apiResponse(
          'No user found with the provided identifier. Please verify and try again.',
          null,
          { status: 'error', code: 'USER_NOT_FOUND', userId },
        );
      }

      const prevRole = user.role;
      user.role = newRole;
      await user.save();

      this.logger.log(
        `✅ User ${user.email} role changed from ${prevRole} → ${newRole} (tenantId=${req.tenantId})`,
      );

      return apiResponse(
        'User role has been updated successfully.',
        {
          id: user._id,
          username: user.username,
          email: user.email,
          previousRole: prevRole,
          newRole: user.role,
        },
        { status: 'success', code: 'USER_ROLE_UPDATED' },
      );
    } catch (err: any) {
      this.logger.error(
        `❌ Unexpected error while changing user role (tenantId=${req.tenantId}, userId=${userId})`,
        err?.stack || err,
      );
      return apiResponse(
        'Role update failed due to a system error. Please try again later.',
        null,
        {
          status: 'error',
          code: 'INTERNAL_ERROR',
          error: err.message || 'Unknown error',
        },
      );
    }
  }

  // ───────────────────────────────
  // HELPERS
  // ───────────────────────────────
  private maskEmail(email: string) {
    const [name, domain] = email.split('@');
    return name[0] + '***@' + domain;
  }

  private extractAccessToken(req: any): string | null {
    const auth = req.headers?.authorization || req.headers?.Authorization;
    if (auth && typeof auth === 'string') {
      const [scheme, value] = auth.trim().split(/\s+/);
      if (/^Bearer$/i.test(scheme) && value) return value;
      if (!/\s/.test(auth)) return auth;
    }

    const xToken = req.headers?.['x-access-token'];
    if (xToken && typeof xToken === 'string') return xToken.trim();

    const cookies = req.cookies || {};
    if (cookies.AccessToken) return String(cookies.AccessToken);
    if (cookies.authorization) return String(cookies.authorization);

    return null;
  }
}
