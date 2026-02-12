# ✅ Step 8.2: Account Lockout & Unlock

## 🎯 Goal

*   Enhance login security by:
*   Tracking failed login attempts (wrong password or wrong OTP).
*   Locking the account after too many failures.
*   Sending an unlock email with a secure token.
*   Allowing account unlock via `/auth/unlock?token=....`

## ⚙️ 1) Environment Configuration

**File:** `.env`
```dotenv
# Lockout configuration
LOGIN_MAX_ATTEMPTS=7
LOGIN_LOCK_MINUTES=60
```
`LOGIN_MAX_ATTEMPTS`: number of failed login attempts before lock.
`LOGIN_LOCK_MINUTES`: lock duration (in minutes).

## ⚙️ 2) Redis Keys

We’ll use two types of Redis keys:
*   `login:fail:<tenantId>:<userId>` → counter of failed logins (TTL = `LOGIN_LOCK_MINUTES`).
*   `unlock:<token>` → JSON payload `{ tenantId, userId }` (TTL = 24h).

## ⚙️ 3) Email Template

**File:** `libs/email-lib/src/templates/account-locked.template.ts`
```typescript
export const accountLockedTemplate = `
<table width="100%" cellpadding="0" cellspacing="0" style="font-family:Arial,sans-serif;background:#f5f7fb;padding:24px;">
  <tr>
    <td align="center">
      <table width="600" style="background:#fff;border-radius:12px;box-shadow:0 8px 24px rgba(30,42,62,0.08);overflow:hidden;">
        <tr>
          <td style="background:#ef4444;color:#fff;text-align:center;padding:20px;">
            <h1 style="margin:0;font-size:20px;">Account Locked</h1>
          </td>
        </tr>
        <tr>
          <td style="padding:28px;text-align:center;">
            <h2 style="margin:0 0 12px;font-size:22px;color:#1f2937;">Hello {{name}},</h2>
            <p style="font-size:15px;color:#374151;">
              Too many failed login attempts have locked your DARMIST Lab account.
            </p>
            <p style="margin:20px 0;font-size:14px;">
              Click the button below to unlock your account:
            </p>
            <a href="{{unlockUrl}}" style="display:inline-block;padding:12px
24px;background:#0d6efd;color:#fff;border-radius:6px;text-decoration:none;font-weight:600;">
              Unlock My Account
            </a>
            <p style="margin-top:24px;font-size:13px;color:#6b7280;">
              If you did not try to log in, please change your password once you regain access.
            </p>
            <p style="font-size:13px;color:#6b7280;margin: 50px 0 0;border-top: 1px solid #6b728084;padding-top: 10px;">Warm regards,<br>DARMIST Lab Team</p>
          </td>
        </tr>
        <tr>
          <td style="background:#f9fafb;text-align:center;padding:14px;font-size:12px;color:#6b7280;">
            &copy; {{year}} DARMIST Lab — All rights reserved.
          </td>
        </tr>
      </table>
    </td>
  </tr>
</table>
`;
```

## ⚙️ 4) Auth Service — Lockout & Unlock Logic

**File:** `apps/auth-service/src/auth-service.service.ts`
(add inside the class, alongside existing `signup` method)
```typescript
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
        await this.recordFailedAttempt(
          req.tenantId,
          conn,
          user._id,
          user.email,
          user.name,
        );
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
        ip: req.ip || req.connection?.remoteAddress || 'N/A',
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

      const appBaseUrl = this.config.get<string>('APP_BASE_URL', 'http://localhost:3000');
      const unlockUrl = `${appBaseUrl}/auth/unlock?token=${unlockToken}`;

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

      let parsed: { tenantId: string; userId: string };
      try {
        parsed = typeof data === 'string' ? JSON.parse(data) : data;
      } catch (err) {
        this.logger.error(
          `❌ Failed to parse unlock token data`,
          err?.stack || '',
        );
        return apiResponse(
          'Unlock request failed due to corrupted token data. Please generate a new unlock link.',
          null,
          {
            status: 'error',
            code: 'TOKEN_DATA_CORRUPTED',
          },
        );
      }

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
      await this.redis.del(`login:fail:${tenantId}:${userId}`); // Clear failed attempts after unlock

      this.logger.log(
        `✅ Account unlocked successfully: user=${userId}, tenant=${tenantId}`,
      );
      return apiResponse(
        'Your account has been unlocked successfully. You may now log in again.',
        { userId, tenantId },
        {
          status: 'success',
          code: 'ACCOUNT_UNLOCKED',
        },
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
  // HELPERS
  // ───────────────────────────────
  private maskEmail(email: string) {
    const [name, domain] = email.split('@');
    return name[0] + '***@' + domain;
  }
}
```

## ⚙️ 5) Controller — Unlock Endpoint

**File:** `apps/auth-service/src/auth-service.controller.ts`
(add inside the controller)
```typescript
import { Get, Query, Body, Controller, Post, Req } from '@nestjs/common';
import { MessagePattern, Payload } from '@nestjs/microservices';
import { apiResponse } from '@app/common-lib';
import { AuthServiceService } from './auth-service.service';
import { LoginDto } from './dto/login.dto';
import { VerifyOtpDto } from './dto/verify-otp.dto';
import { BadRequestException } from '@nestjs/common';

@Controller('auth')
export class AuthServiceController {
  constructor(private readonly service: AuthServiceService) {}

  // ───────────────────────────────
  // HTTP Endpoint: Login (send OTP)
  // ───────────────────────────────
  @Post('login')
  async loginHttp(@Req() req: any, @Body() dto: LoginDto) {
    req.tenantId = req.headers['x-tenant-id'];
    const result = await this.service.login(req, dto);
    return result;
  }

  // ───────────────────────────────
  // HTTP Endpoint: Login → Verify OTP
  // ───────────────────────────────
  @Post('login/verify')
  async verifyOtpHttp(@Req() req: any, @Body() dto: VerifyOtpDto) {
    req.tenantId = req.headers['x-tenant-id'];
    const result = await this.service.verifyOtp(req, dto);
    return result;
  }

  // ───────────────────────────────
  // TCP Endpoint: Login (send OTP)
  // ───────────────────────────────
  @MessagePattern({ cmd: 'auth.login' })
  async loginTcp(@Payload() payload: LoginDto & { tenantConnection?: any }) {
    const result = await this.service.login(
      { tenantConnection: payload.tenantConnection },
      payload,
    );
    return result;
  }

  // ───────────────────────────────
  // TCP Endpoint: Login → Verify OTP
  // ───────────────────────────────
  @MessagePattern({ cmd: 'auth.verifyOtp' })
  async verifyOtpTcp(
    @Payload() payload: VerifyOtpDto & { tenantConnection?: any },
  ) {
    const result = await this.service.verifyOtp(
      { tenantId: payload.tenantConnection },
      payload,
    );
    return result;
  }

  // ───────────────────────────────
  // HTTP Endpoint: Unlock account
  // ───────────────────────────────
  @Get('unlock')
  async unlockHttp(@Req() req: any, @Query('token') token: string) {
    const conn = req.tenantConnection;
    if (!conn) throw new BadRequestException('Tenant connection not available');
    req.tenantId = req.headers['x-tenant-id'];
    const result = await this.service.unlock(token, conn);
    return result;
  }

  // ───────────────────────────────
  // TCP Endpoint: Unlock account
  // ───────────────────────────────
  @MessagePattern({ cmd: 'auth.unlock' })
  async unlockTcp(
    @Payload() payload: { token: string; tenantConnection: any },
  ) {
    const result = await this.service.unlock(
      payload.token,
      payload.tenantConnection,
    );
    return result;
  }
}
```

## ⚙️ 6) cURL Tests

a) Exceed wrong password attempts
```bash
for i in {1..8}; do
curl -s -X POST http://localhost:3502/auth/login \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: darmist1" \
  -d '{"usernameOrEmailOrMobile":"testuser","password":"wrong"}' | jq
done
```
After 7 failures, account is locked. Unlock email is sent.

b) Unlock account
```bash
curl   -H "Content-Type: application/json" -H "x-tenant-id: darmist1" "http://localhost:3502/auth/unlock?token=71da8c27-a42b-4497-85f3-8f9f55dd230e" | jq
```

Expected (200):
```json
{
  "message": "Your account has been unlocked successfully. You may now log in again.",
  "data": {
    "userId": "690c30f4b16e95915801e4e5",
    "tenantId": "darmist1"
  },
  "meta": {
    "status": "success",
    "code": "ACCOUNT_UNLOCKED"
  },
  "ts": "2025-11-06T06:48:11.258Z"
}
```

## 🎉 End of Step 8.2

You now have:
*   Lockout after too many failures
*   Unlock via email link
