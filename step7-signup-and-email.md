# ✅ Step 7 — Signup + Welcome Email

## 🎯 Goal

*   Build a reusable `email-lib` for sending HTML + plain-text emails.
*   Use it in `auth-service` to send a welcome email after signup.
*   Implement signup endpoint in `auth-service` with fields:
    *   `name`, `username`, `email`, `mobile`, `password`
*   Defaults: `role = user`, `status = 1`
*   Hash passwords with `bcrypt`.
*   Add both HTTP endpoints and TCP endpoints in `auth-service`.

## ⚙️ 1) Environment Variables

Add SMTP config in `.env` (already available in your project):
```dotenv
SMTP_HOST=mail.darmist.com
SMTP_PORT=465
SMTP_SECURE=true
SMTP_USER=nestjs_tutorial@darmist.com
SMTP_PASS="YourSecreetPassword@2025"
EMAIL_FROM="DARMIST Lab" <nestjs_tutorial@darmist.com>
```

## ⚙️ 2) Install Dependencies

```bash
npm install nodemailer handlebars bcrypt
npm install -D @types/nodemailer @types/bcrypt
```

## ⚙️ 3) Email Library

### Service

**File:** `libs/email-lib/src/email-lib.service.ts`
```typescript
import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
nodemailer, { Transporter } from 'nodemailer';
import handlebars from 'handlebars';

/**
 * EmailLibService
 * ----------------
 * - Sends emails using SMTP (via Nodemailer).
 * - Supports both HTML template and plain-text fallback.
 */
@Injectable()
export class EmailLibService {
  private readonly logger = new Logger(EmailLibService.name);
  private transporter: Transporter;

  constructor(private readonly config: ConfigService) {
    this.transporter = nodemailer.createTransport({
      host: this.config.get('SMTP_HOST'),
      port: this.config.get<number>('SMTP_PORT'),
      secure: this.config.get<boolean>('SMTP_SECURE'),
      auth: {
        user: this.config.get('SMTP_USER'),
        pass: this.config.get('SMTP_PASS'),
      },
    });
  }

  /**
   * Send an email
   * @param to Recipient email
   * @param subject Subject line
   * @param template HTML template string with placeholders (handlebars)
   * @param context Variables for handlebars template
   * @param plainText Optional plain text fallback
   */
  async sendMail(
    to: string,
    subject: string,
    template: string,
    context: Record<string, any>,
    plainText?: string,
  ) {
    try {
      const compiled = handlebars.compile(template);
      const html = compiled(context);

      const mailOptions = {
        from: this.config.get('EMAIL_FROM'),
        to,
        subject,
        text: plainText ?? subject,
        html,
      };

      const info = await this.transporter.sendMail(mailOptions);
      this.logger.log(`📧 Email sent to ${to}: ${info.messageId}`);
      return info;
    } catch (err) {
      this.logger.error(`❌ Failed to send email to ${to}`, err.stack);
      throw err;
    }
  }
}
```

### Module

**File:** `libs/email-lib/src/email-lib.module.ts`
```typescript
import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { EmailLibService } from './email-lib.service';

@Module({
  imports: [ConfigModule],
  providers: [EmailLibService],
  exports: [EmailLibService],
})
export class EmailLibModule {}
```

### Template

**File:** `libs/email-lib/src/templates/welcome.template.ts`
```typescript
/**
 * welcomeTemplate — Professional, branded welcome email
 * Usage: sendMail(to, subject, welcomeTemplate, { name, email, year }, textFallback)
 */
export const welcomeTemplate = `
<table width="100%" cellpadding="0" cellspacing="0" style="font-family:Arial,sans-serif;background:#f5f7fb;padding:24px;">
  <tr>
    <td align="center">
      <table width="600" cellpadding="0" cellspacing="0" style="background:#ffffff;border-radius:12px;overflow:hidden;box-shadow:0 8px 24px 
rgba(30,42,62,0.08);">
        <tr>
          <td style="background:#0d6efd;color:#ffffff;text-align:center;padding:22px;">
            <div style="font-size:20px;font-weight:600;letter-spacing:0.3px;">DARMIST Lab</div>
            <div style="opacity:0.9;font-size:12px;margin-top:4px;">Welcome to the community</div>
          </td>
        </tr>
        <tr>
          <td style="padding:32px 28px;text-align:center;">
            <h2 style="margin:0 0 12px;font-size:22px;color:#1f2937;">Welcome, {{name}}</h2>
            <p style="margin:0 0 16px;font-size:15px;color:#374151;">
              Hi {{name}}, thanks for signing up with DARMIST Lab. Your account has been created successfully.
            </p>
            <p style="margin:0 0 20px;font-size:15px;color:#374151;">
              You can now log in using your email <strong>{{email}}</strong>.
            </p>
            <p style="font-size:13px;color:#6b7280;margin:0;">
              We’re excited to have you on board. Let’s build something amazing together!
            </p>
            <p style="font-size:13px;color:#6b7280;margin: 50px 0 0;border-top: 1px solid #6b728084;padding-top: 10px;">
              Warm regards,<br>DARMIST Lab Team
            </p>
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

## ⚙️ 4) User Schema in Auth Service

**File:** `apps/auth-service/src/schemas/user.schema.ts`
```typescript
import { Schema } from 'mongoose';

export const UserSchema = new Schema(
  {
    name: { type: String, required: true },
    username: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    mobile: { type: String, required: true },
    password: { type: String, required: true },
    role: { type: String, enum: ['user', 'manager', 'admin'], default: 'user' },
    status: { type: Number, default: 1 },
  },
  { timestamps: true },
);
```

## ⚙️ 5) DTO for Signup

**File:** `apps/auth-service/src/dto/signup.dto.ts`
```typescript
import { IsEmail, IsString, MinLength } from 'class-validator';

export class SignupDto {
  @IsString()
  name: string;

  @IsString()
  username: string;

  @IsEmail()
  email: string;

  @IsString()
  mobile: string;

  @IsString()
  @MinLength(6)
  password: string;
}
```

## ⚙️ 6) Auth Service Module

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

@Module({
  imports: [
    ConfigModule.forRoot({ isGlobal: true }),
    RedisLibModule,
    ClientsModule.registerAsync([
      {
        name: 'TENANT_SERVICE',
        inject: [ConfigService],
        useFactory: (cfg: ConfigService) => ({
          transport: Transport.TCP,
          options: {
            host: '0.0.0.0',
            port: cfg.get<number>('TENANT_SERVICE_TCP_PORT', 4503),
          },
        }),
      },
    ]),
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

## ⚙️ 7) Auth Service (Business Logic)

**File:** `apps/auth-service/src/auth-service.service.ts`
```typescript
import { Injectable, Logger } from '@nestjs/common';
import { apiResponse } from '@app/common-lib';
import { SignupDto } from './dto/signup.dto';
import { UserSchema } from './schemas/user.schema';
import { EmailLibService } from '@app/email-lib';
import * as bcrypt from 'bcrypt';
import { welcomeTemplate } from '@app/email-lib/templates/welcome.template';

@Injectable()
export class AuthServiceService {
  private readonly logger = new Logger(AuthServiceService.name);

  constructor(private readonly mailer: EmailLibService) {}

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
          `❌ Tenant connection missing for signup: ${dto.email}`
        );
        return apiResponse(
          'Signup failed: Tenant environment is not initialized. Please retry after selecting the correct workspace or tenant.',
          null,
          {
            status: 'error',
            code: 'TENANT_CONNECTION_MISSING',
            details: { email: dto.email },
          }
        );
      }

      const User = conn.model('User', UserSchema);
      const hashed = await bcrypt.hash(dto.password, 10);

      const user = new User({ ...dto, password: hashed });
      const saved = await user.save();

      this.logger.log(
        `✅ New user created: ${saved.username} (${saved.email})`
      );

      try {
        await this.mailer.sendMail(
          dto.email,
          'Welcome to DARMIST Lab',
          welcomeTemplate,
          { name: dto.name, email: dto.email },
          `Welcome ${dto.name}, your account has been created successfully.`
        );
        this.logger.log(`📧 Welcome email sent to ${dto.email}`);
      } catch (emailErr) {
        this.logger.error(
          `📧 Failed to send welcome email to ${dto.email}`,
          emailErr.stack
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
        }
      );
    } catch (err: any) {
      if (err?.code === 11000 && err?.keyValue) {
        const fields = Object.keys(err.keyValue);
        const duplicates = fields.map((f) => `${f} "${err.keyValue[f]}"` );
        this.logger.warn(
          `⚠️ Duplicate signup attempt: ${duplicates.join(', ')}`
        );
        return apiResponse(
          'Signup failed: Some information already exists in the system. Please use different values.',
          null,
          {
            status: 'error',
            code: 'DUPLICATE_ENTRY',
            message: `Duplicate fields: ${duplicates.join(', ')}`,
          }
        );
      }

      if (err?.name === 'ValidationError') {
        const messages = Object.values(err.errors).map(
          (e: any) => e.message || e
        );
        this.logger.warn(
          `⚠️ Validation failed for signup: ${messages.join(', ')}`
        );
        return apiResponse(
          'Signup failed due to invalid or missing information. Please review your inputs.',
          null,
          {
            status: 'error',
            code: 'VALIDATION_FAILED',
            message: messages.join(', '),
          }
        );
      }

      this.logger.error(
        `❌ Unexpected signup error: ${err.message}`,
        err.stack
      );
      return apiResponse(
        'Signup failed due to a system error. Please try again later.',
        null,
        {
          status: 'error',
          code: 'INTERNAL_ERROR',
          error: err.message || 'Unknown error',
        }
      );
    }
  }
}
```

## ⚙️ 8) Auth Controller (HTTP + TCP)

**File:** `apps/auth-service/src/auth-service.controller.ts`
```typescript
import { Body, Controller, Get, Post, Req } from '@nestjs/common';
import { MessagePattern, Payload } from '@nestjs/microservices';
import { AuthServiceService } from './auth-service.service';
import { SignupDto } from './dto/signup.dto';

@Controller('auth')
export class AuthServiceController {
  constructor(private readonly service: AuthServiceService) {}

  // ───────────────────────────────
  // HTTP Endpoint: Signup
  // ───────────────────────────────
  @Post('signup')
  async signupHttp(@Req() req: any, @Body() dto: SignupDto) {
    const result = await this.service.signup(req, dto);
    return result;
  }

  // ───────────────────────────────
  // TCP Endpoint: Signup
  // ───────────────────────────────
  @MessagePattern({ cmd: 'auth.signup' })
  async signupTcp(@Payload() payload: SignupDto & { tenantConnection?: any }) {
    const result = await this.service.signup(
      { tenantConnection: payload.tenantConnection },
      payload,
    );
    return result;
  }

  // ───────────────────────────────
  // HTTP Endpoint: Health check
  // ───────────────────────────────
  @Get('health')
  health() {
    return { ok: true, service: 'auth-service', mode: 'HTTP' };
  }
}
```

## ⚙️ 9) Verify Signup + Email

Start tenant-service + auth-service:
```bash
npx nest start tenant-service --watch
npx nest start auth-service --watch
```

Create a tenant (`darmist1`) and set status to ACTIVE.

Signup user:
```bash
curl -X POST http://localhost:3502/auth/signup \
  -H "x-tenant-id: darmist1" \
  -H "Content-Type: application/json" \
  -d 
  {
    "name": "Alice",
    "username": "alice01",
    "email": "alice@darmist.com",
    "mobile": "1234567890",
    "password": "secret123"
  }
 | jq
```

Response:
```json
{
  "message": "Your account has been created successfully. You can now log in to your workspace.",
  "data": {
    "id": "690c1e0ad8bbb0d1347f64d7",
    "name": "Alice",
    "username": "alice01",
    "email": "alice@darmist.com",
    "role": "user"
  },
  "meta": {
    "status": "success",
    "code": "USER_CREATED"
  },
  "ts": "2025-11-06T04:03:25.909Z"
}
```

Check your inbox → You should receive a Welcome Email.

## 🎉 End of Step 7

*   Added `email-lib` (HTML + plain-text).
*   Integrated into `auth-service`.
*   Implemented signup with password hashing + welcome email.
