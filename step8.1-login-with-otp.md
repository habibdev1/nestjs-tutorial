# ✅ Step 8.1: Login & Login with OTP (Email + Redis + JWT)

## 🎯 Goal

*   Login using username/email/mobile + password
*   Generate & email a 6-digit OTP (expires in 5 minutes)
*   Verify OTP and issue JWT access + refresh tokens
*   Keep existing signup code unchanged — we will only add new code

## ⚙️ 0) Install & Env

a) Install required packages
```bash
npm i @nestjs/jwt jsonwebtoken
npm i -D @types/jsonwebtoken
```

b) Verify env in `.env`
```dotenv
# ── Security (JWT) ────────────────────────────────────
JWT_SECRET=AeroStitch@2000
PASSWORD_SALT_ROUNDS=10
JWT_EXPIRES_IN=7d
JWT_REFRESH_EXPIRES_IN=365d
# ─ Brute-force / Lock settings ─
LOGIN_MAX_ATTEMPTS=7
LOGIN_LOCK_MINUTES=60
```

## ⚙️ 1) DTOs

**File:** `apps/auth-service/src/dto/login.dto.ts`
```typescript
import { IsString, IsNotEmpty } from 'class-validator';

export class LoginDto {
  @IsString() @IsNotEmpty()
  usernameOrEmailOrMobile: string;

  @IsString() @IsNotEmpty()
  password: string;
}
```

**File:** `apps/auth-service/src/dto/verify-otp.dto.ts`
```typescript
import { IsString, IsNotEmpty, IsUUID, Length } from 'class-validator';

export class VerifyOtpDto {
  @IsUUID()
  loginId: string; // temporary ID that ties to OTP record in Redis

  @IsString() @IsNotEmpty() @Length(6, 6)
  otp: string;

  @IsString()
  deviceName?: string; // optional label e.g. "Chrome on Mac"
}
```

## ⚙️ 2) Email Template — placed in email-lib

**File:** `libs/email-lib/src/templates/otp-login.template.ts`
```typescript
/**
 * otpLoginTemplate — Professional, branded OTP email
 * Usage: sendMail(to, subject, otpLoginTemplate, { name, otp, year }, textFallback)
 */
export const otpLoginTemplate = `
<table width="100%" cellpadding="0" cellspacing="0" style="font-family:Arial,sans-serif;background:#f5f7fb;padding:24px;">
  <tr>
    <td align="center">
      <table width="600" cellpadding="0" cellspacing="0" style="background:#ffffff;border-radius:12px;overflow:hidden;box-shadow:0 8px 24px 
rgba(30,42,62,0.08);">
        <tr>
          <td style="background:#0d6efd;color:#ffffff;text-align:center;padding:22px;">
            <div style="font-size:20px;font-weight:600;letter-spacing:0.3px;">DARMIST Lab</div>
            <div style="opacity:0.9;font-size:12px;margin-top:4px;">Secure Login Verification</div>
          </td>
        </tr>
        <tr>
          <td style="padding:32px 28px;text-align:center;">
            <h2 style="margin:0 0 12px;font-size:22px;color:#1f2937;">Hello {{name}},</h2>
            <p style="margin:0 0 18px;font-size:15px;color:#374151;">
              Use the One-Time Password (OTP) below to continue your login.
            </p>
            <div style="display:inline-block;margin:10px 0 18px;padding:12px 22px;border:2px dashed 
#0d6efd;border-radius:10px;font-size:30px;font-weight:700;color:#0d6efd;letter-spacing:6px;background:#f0f6ff;">
              {{otp}}
            </div>
            <p style="font-size:13px;color:#6b7280;margin:0 0 4px;">This code will expire in <strong>5 minutes</strong>.</p>
            <p style="font-size:12px;color:#9ca3af;margin:0;">If you didn’t request this, you can safely ignore this email.</p>
            <p style="font-size:13px;color:#6b7280;margin: 50px 0 0;border-top: 1px solid #6b728084;padding-top: 10px;">Warm regards,<br>DARMIST Lab Team</p>
          </td>
        </tr>
        <tr>
          <td style="background:#f9fafb;text-align:center;padding:14px;color:#6b7280;font-size:12px;">
            &copy; {{year}} DARMIST Lab — All rights reserved.
          </td>
        </tr>
      </table>
    </td>
  </tr>
</table>
`;
```

## ⚙️ 3) User Schema

```typescript
import { Schema } from 'mongoose';

export const SessionSchema = new Schema(
  {
    sessionId: { type: String, required: true },
    deviceName: { type: String },
    ip: { type: String },
    ua: { type: String },
    refreshHash: { type: String },
    createdAt: { type: Date, default: Date.now },
    lastSeen: { type: Date, default: Date.now },
    revokedAt: { type: Date },
  },
  { _id: false },
);

export const UserSchema = new Schema(
  {
    name: { type: String, required: true },
    username: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    mobile: { type: String, required: true },
    password: { type: String, required: true },
    role: { type: String, enum: ['user', 'manager', 'admin'], default: 'user' },
    status: { type: Number, default: 1 }, // 1 = active
    sessions: { type: [SessionSchema], default: [] }, // 👈 for Step 8.3
  },
  { timestamps: true },
);
```

## ⚙️ 4) Module — Register JwtModule

**File:** `apps/auth-service/src/auth-service.module.ts`
```typescript
import { Module, MiddlewareConsumer } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { ClientsModule, Transport } from '@nestjs/microservices';
import { RedisLibModule } from '@app/redis-lib';
import { DatabaseLibService } from '@app/database-lib';
import { TenantMiddleware } from '@app/database-lib/tenant.middleware';
import { AuthServiceService } from './auth-service.service';
import { EmailLibService } from '@app/email-lib';
import { AuthServiceController } from './auth-service.controller';
import { JwtModule } from '@nestjs/jwt';

@Module({
  imports: [
    ConfigModule.forRoot({ isGlobal: true }),
    RedisLibModule,
    JwtModule.registerAsync({
      inject: [ConfigService],
      useFactory: (cfg: ConfigService) => {
        const expiresIn = cfg.get<string>('JWT_EXPIRES_IN', '15m');
        return {
          secret: cfg.get<string>('JWT_SECRET'),
          signOptions: { expiresIn: expiresIn as any },
        };
      },
    }),
    ClientsModule.registerAsync({
      name: 'TENANT_SERVICE',
      inject: [ConfigService],
      useFactory: (cfg: ConfigService) => ({
        transport: Transport.TCP,
        options: {
          host: '0.0.0.0',
          port: cfg.get<number>('TENANT_SERVICE_TCP_PORT', 4503),
        },
      }),
    }),
  ],
  controllers: [AuthServiceController],
  providers: [AuthServiceService, DatabaseLibService, EmailLibService],
})
export class AuthServiceModule {
  configure(consumer: MiddlewareConsumer) {
    consumer.apply(TenantMiddleware).forRoutes('*');
  }
}
```

## ⚙️ 5) Service — Add Login & Verify methods (keep signup as-is)

**File:** `apps/auth-service/src/auth-service.service.ts`
🔵 Important: Do not delete your existing `signup()` implementation. Add the following methods in the same class (imports first).
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
  // HELPERS
  // ───────────────────────────────
  private maskEmail(email: string) {
    const [name, domain] = email.split('@');
    return name[0] + '***@' + domain;
  }
}
```

## ⚙️ 6) Controller — Add Endpoints

**File:** `apps/auth-service/src/auth-service.controller.ts`
(Append below your existing signup handlers.)
```typescript
import { Body, Controller, Post, Req } from '@nestjs/common';
import { MessagePattern, Payload } from '@nestjs/microservices';
import { apiResponse } from '@app/common-lib';
import { AuthServiceService } from './auth-service.service';
import { LoginDto } from './dto/login.dto';
import { VerifyOtpDto } from './dto/verify-otp.dto';

@Controller('auth')
export class AuthServiceController {
  constructor(private readonly service: AuthServiceService) {}

  // ───────────────────────────────
  // HTTP Endpoint: Login (send OTP)
  // ───────────────────────────────
  @Post('login')
  async loginHttp(@Req() req: any, @Body() dto: LoginDto) {
    const result = await this.service.login(req, dto);
    return result;
  }

  // ───────────────────────────────
  // HTTP Endpoint: Login → Verify OTP
  // ───────────────────────────────
  @Post('login/verify')
  async verifyOtpHttp(@Req() req: any, @Body() dto: VerifyOtpDto) {
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
      { tenantConnection: payload.tenantConnection },
      payload,
    );
    return result;
  }
}
```

## ⚙️ 7) cURL Tests

a) Signup
```bash
curl -X POST http://localhost:3502/auth/signup \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: darmist1" \
  -d '{
    "name": "Test User",
    "username": "testuser",
    "email": "testuser@darmist.com",
    "mobile": "01710000000",
    "password": "secret123"
  }' | jq
```

b) Request OTP
```bash
curl -X POST http://localhost:3502/auth/login \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: darmist1" \
  -d '{"usernameOrEmailOrMobile":"testuser","password":"secret123"}' | jq
```

Expected (200):
```json
{
  "message": "A verification OTP has been sent to your registered email address. Please check your inbox.",
  "data": {
    "loginId": "c1e0d2ba-237e-47e1-b18b-d86a092c4058",
    "channel": "email",
    "maskedEmail": "t***@darmist.com"
  },
  "meta": {
    "status": "success",
    "code": "OTP_SENT"
  },
  "ts": "2025-11-06T05:24:58.249Z"
}
```

c) Verify OTP
```bash
curl -X POST http://localhost:3502/auth/login/verify \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: darmist1" \
  -d '{"loginId":"c1e0d2ba-237e-47e1-b18b-d86a092c4058","otp":"903335"}' | jq
```

Expected (200):
```json
{
  "message": "You have successfully logged in to DARMIST Lab.",
  "data": {
    "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI2OTBjMzBmNGIxNmU5NTkxNTgwMWU0ZTUiLCJ1c2VybmFtZSI6InRlc3R1c2VyIiwicm9sZSI6InVzZXIiLCJzaWQiOiJlOGM3ZmE1Zi0xNjZiLTRkZTItYjJlNC0yZDI5MGM1N2NmNTgiLCJpYXQiOjE3NjI0MDY3ODUsImV4cCI6MTc2MzAxMTU4NX0.PdZzsgGRAJkfJgodjwnkW8vY-IZqI5uevkU_BGk3W0w",
    "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI2OTBjMzBmNGIxNmU5NTkxNTgwMWU0ZTUiLCJ1c2VybmFtZSI6InRlc3R1c2VyIiwicm9sZSI6InVzZXIiLCJzaWQiOiJlOGM3ZmE1Zi0xNjZiLTRkZTItYjJlNC0yZDI5MGM1N2NmNTgiLCJpYXQiOjE3NjI0MDY3ODUsImV4cCI6MTc5Mzk0Mjc4NX0.gCdRm6N-UFKYvGxe09pzo_MkL6Hkg7wrW-Ff90KNWeY",
    "sessionId": "e8c7fa5f-166b-4de2-b2e4-2d290c57cf58",
    "user": {
      "id": "690c30f4b16e95915801e4e5",
      "username": "testuser",
      "role": "user"
    }
  },
  "meta": {
    "status": "success",
    "code": "LOGIN_SUCCESS"
  },
  "ts": "2025-11-06T05:26:25.829Z"
}
```

d) Wrong password (should not reveal which field)
```bash
curl -X POST http://localhost:3502/auth/login \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: darmist1" \
  -d '{"usernameOrEmailOrMobile":"testuser","password":"wrong"}' | jq
```

Expected (401):
```json
{
  "message": "Incorrect password. Please try again or reset your password if forgotten.",
  "data": null,
  "meta": {
    "status": "error",
    "code": "INVALID_PASSWORD",
    "field": "password"
  },
  "ts": "2025-11-06T05:31:44.081Z"
}
```

e) Wrong OTP
```bash
curl -X POST http://localhost:3502/auth/login/verify \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: darmist1" \
  -d '{"loginId":"e2b8f7a2-....-4a9c","otp":"000000"}'
```

Expected (401):
`"Invalid OTP"`

## 🎉 End of Step 8.1

You now have:
*   Login → OTP email (5 min TTL) → Verify → JWT tokens
*   A polished email template and complete cURL test set
