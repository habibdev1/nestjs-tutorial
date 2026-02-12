# ✅ Step 8.3: Loggedin Devices, Logout, and Refresh Tokens

## 🎯 Goal

*   Track logged-in devices/sessions in MongoDB.
*   Add endpoints to:
    *   List active sessions
    *   Logout single session
    *   Logout all sessions
    *   Refresh tokens (with rotation)
*   Protect everything using JWT Guard.
*   One shared library (`auth-lib`) exporting:
    *   `JwtStrategy`
    *   `JwtAuthGuard` (honors `@Public()`)
    *   `@Public()` decorator
    *   `@Roles()` decorator
    *   `RolesGuard`
*   `api-gateway` configured with global guards:
    *   All routes require JWT by default
    *   Routes marked `@Public()` bypass JWT
    *   Routes marked `@Roles(...)` additionally enforce role checks

## ⚙️ 1) Install Required Packages and Update Environment Variables

```bash
npm install @nestjs/passport passport passport-jwt
npm install @types/passport-jwt --save-dev
```

## ⚙️ 2) Guards

### A. JWT strategy (shared)

**File:** `libs/auth-lib/src/jwt.strategy.ts`
```typescript
import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy, 'jwt') {
  constructor(private readonly configService: ConfigService) {
    const jwtSecret = configService.get<string>('JWT_SECRET');
    if (!jwtSecret) throw new Error('JWT_SECRET must be defined');

    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      secretOrKey: jwtSecret,
      ignoreExpiration: false,
    });
  }

  // Expected payload from auth-service:
  // { sub, tenantId, role, sid?, iat, exp }
  async validate(payload: any) {
    return payload;
  }
}
```

### B. Decorators (Public & Roles)

**File:** `libs/auth-lib/src/decorators/public.decorator.ts`
```typescript
import { SetMetadata } from '@nestjs/common';
export const IS_PUBLIC_KEY = 'isPublic';
export const Public = () => SetMetadata(IS_PUBLIC_KEY, true);
```

**File:** `libs/auth-lib/src/decorators/roles.decorator.ts`
```typescript
import { SetMetadata } from '@nestjs/common';
export type AppRole = 'user' | 'manager' | 'admin';
export const ROLES_KEY = 'app_roles_required';
export const Roles = (...roles: AppRole[]) => SetMetadata(ROLES_KEY, roles);
```

### C. Guards (JWT that honors @Public, and RolesGuard)

**File:** `libs/auth-lib/src/guards/jwt-auth.guard.ts`
```typescript
import { Injectable, ExecutionContext } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { Reflector } from '@nestjs/core';
import { IS_PUBLIC_KEY } from '../decorators/public.decorator';

@Injectable()
export class JwtAuthGuard extends AuthGuard('jwt') {
  constructor(private readonly reflector: Reflector) {
    super();
  }

  canActivate(context: ExecutionContext) {
    // Allow routes marked @Public() without JWT
    const isPublic = this.reflector.getAllAndOverride<boolean>(IS_PUBLIC_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);
    if (isPublic) return true;
    return super.canActivate(context);
  }
}
```

**File:** `libs/auth-lib/src/guards/roles.guard.ts`
```typescript
import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Injectable,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { ROLES_KEY, AppRole } from '../decorators/roles.decorator';

@Injectable()
export class RolesGuard implements CanActivate {
  constructor(private readonly reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const required = this.reflector.getAllAndOverride<AppRole[]>(ROLES_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);
    if (!required || required.length === 0) return true;

    const req = context.switchToHttp().getRequest();
    const role = req?.user?.role as AppRole | undefined;
    if (!role) throw new ForbiddenException('Missing role');
    if (required.includes(role)) return true;

    throw new ForbiddenException(
      `Insufficient role. Required: ${required.join(', ')}`
    );
  }
}
```

### D. DTOs

**File:** `apps/auth-service/src/dto/refresh.dto.ts`
```typescript
import { IsString } from 'class-validator';

export class RefreshDto {
  @IsString()
  refreshToken: string;
}
```

**File:** `apps/auth-service/src/dto/logout-session.dto.ts`
```typescript
import { IsUUID } from 'class-validator';

export class LogoutSessionDto {
  @IsUUID()
  sessionId: string;
}
```

### E. Barrel export

**File:** `libs/auth-lib/src/index.ts`
```typescript
export * from './auth-lib.module';
export * from './auth-lib.service';

// Strategy + Guards
export * from './jwt.strategy';
export * from './guards/jwt-auth.guard';
export * from './guards/jwt-session.guard';
export * from './guards/roles.guard';

// Decorators
export * from './decorators/public.decorator';
export * from './decorators/roles.decorator';
```

## ⚙️ 3) Auth Service Updates

**File:** `apps/auth-service/src/auth-service.service.ts`
```typescript
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
```

## ⚙️ 4) Controller

**File:** `apps/auth-service/src/auth-service.controller.ts`
```typescript
import {
  BadRequestException,
  Body,
  Controller,
  Get,
  Post,
  Query,
  Req,
  UseGuards,
} from '@nestjs/common';
import { MessagePattern, Payload } from '@nestjs/microservices';
import { AuthServiceService } from './auth-service.service';
import { SignupDto } from './dto/signup.dto';
import { VerifyOtpDto } from './dto/verify-otp.dto';
import { LoginDto } from './dto/login.dto';
import { JwtAuthGuard, Public } from '@app/auth-lib';
import { DatabaseLibService } from '@app/database-lib';
import { LogoutSessionDto } from './dto/logout-session.dto';
import { RefreshDto } from './dto/refresh.dto';

@Controller('auth')
export class AuthServiceController {
  constructor(
    private readonly databaseLibService: DatabaseLibService,
    private readonly service: AuthServiceService,
  ) {}

  // ───────────────────────────────
  // HTTP Endpoint: Signup
  // ───────────────────────────────
  @Public()
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

  // ───────────────────────────────
  // HTTP Endpoint: Login (send OTP)
  // ───────────────────────────────
  @Public()
  @Post('login')
  async loginHttp(@Req() req: any, @Body() dto: LoginDto) {
    req.tenantId = req.headers['x-tenant-id'];
    const result = await this.service.login(req, dto);
    return result;
  }

  // ───────────────────────────────
  // HTTP Endpoint: Login → Verify OTP
  // ───────────────────────────────
  @Public()
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
  @Public()
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

  // ───────────────────────────────
  // HTTP: Sessions
  // ───────────────────────────────
  @UseGuards(JwtAuthGuard)
  @Get('sessions')
  async sessionsHttp(@Req() req: any) {
    const result = await this.service.listSessions(req);
    return result;
  }

  // ───────────────────────────────
  // TCP: Sessions
  // ───────────────────────────────
  @MessagePattern({ cmd: 'auth.sessions' })
  async sessionsTcp(
    @Payload()
    payload: {
      tenantId: string;
      req: any;
      ip?: string;
      'user-agent'?: string;
    },
  ) {
    const conn = await this.databaseLibService.getTenantConnection(
      payload.tenantId,
    );

    const req = {
      tenantId: payload.tenantId,
      tenantConnection: conn,
      user: payload?.req?.user,
      headers: { 'user-agent': payload['user-agent'] || 'tcp-client' },
      ip: payload.ip || '0.0.0.0',
    };
    const result = await this.service.listSessions(req);
    return result;
  }

  // ───────────────────────────────
  // HTTP: Logout Single Session
  // ───────────────────────────────
  @UseGuards(JwtAuthGuard)
  @Post('logout/session')
  async logoutSessionHttp(@Req() req: any, @Body() dto: LogoutSessionDto) {
    const result = await this.service.logoutSession(req, dto.sessionId);
    return result;
  }

  // ───────────────────────────────
  // TCP: Logout Single Session
  // ───────────────────────────────
  @MessagePattern({ cmd: 'auth.logoutSession' })
  async logoutSessionTcp(
    @Payload()
    payload: {
      tenantId: string;
      sessionId: string;
      req: any;
      ip?: string;
      'user-agent'?: string;
    },
  ) {
    const conn = await this.databaseLibService.getTenantConnection(
      payload.tenantId,
    );
    const req = {
      tenantId: payload.tenantId,
      tenantConnection: conn,
      user: payload?.req?.user,
      headers: { 'user-agent': payload['user-agent'] || 'tcp-client' },
      ip: payload.ip || '0.0.0.0',
    };
    const result = await this.service.logoutSession(req, payload.sessionId);
    return result;
  }

  // ───────────────────────────────
  // HTTP: Logout All Sessions
  // ───────────────────────────────
  @UseGuards(JwtAuthGuard)
  @Post('logout/all')
  async logoutAllHttp(@Req() req: any) {
    const result = await this.service.logoutAll(req);
    return result;
  }

  // ───────────────────────────────
  // TCP: Logout All Sessions
  // ───────────────────────────────
  @MessagePattern({ cmd: 'auth.logoutAll' })
  async logoutAllTcp(
    @Payload()
    payload: {
      tenantId: string;
      req?: any;
      ip?: string;
      'user-agent'?: string;
    },
  ) {
    const conn = await this.databaseLibService.getTenantConnection(
      payload.tenantId,
    );
    const req = {
      tenantId: payload.tenantId,
      tenantConnection: conn,
      user: payload?.req?.user,
      headers: { 'user-agent': payload['user-agent'] || 'tcp-client' },
      ip: payload.ip || '0.0.0.0',
    };
    const result = await this.service.logoutAll(req);
    return result;
  }

  // ───────────────────────────────
  // HTTP: Refresh
  // ───────────────────────────────
  @Public()
  @Post('refresh')
  async refreshHttp(@Req() req: any, @Body() dto: RefreshDto) {
    const result = await this.service.refresh(req, dto.refreshToken);
    return result;
  }

  // ───────────────────────────────
  // TCP: Refresh
  // ───────────────────────────────
  @MessagePattern({ cmd: 'auth.refresh' })
  async refreshTcp(
    @Payload()
    payload: {
      tenantId: string;
      refreshToken: string;
      user?: any;
      ip?: string;
      'user-agent'?: string;
    },
  ) {
    const conn = await this.databaseLibService.getTenantConnection(
      payload.tenantId,
    );
    const req = {
      tenantId: payload.tenantId,
      tenantConnection: conn,
      user: payload.user,
      headers: { 'user-agent': payload['user-agent'] || 'tcp-client' },
      ip: payload.ip || '0.0.0.0',
    };
    const result = await this.service.refresh(req, payload.refreshToken);
    return result;
  }
}

```

## ⚙️ 5) Update Module

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
import { PassportModule } from '@nestjs/passport';
import { JwtAuthGuard, JwtStrategy, RolesGuard } from '@app/auth-lib';
import { APP_GUARD } from '@nestjs/core';

@Module({
  imports: [
    ConfigModule.forRoot({ isGlobal: true }),
    RedisLibModule,
    PassportModule.register({ defaultStrategy: 'jwt' }),
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
  providers: [
    AuthServiceService,
    DatabaseLibService,
    EmailLibService,
    JwtStrategy,
    // Global guards: order matters (JWT first, then Session, then Roles)
    { provide: APP_GUARD, useClass: JwtAuthGuard },
    // { provide: APP_GUARD, useClass: JwtSessionGuard },
    { provide: APP_GUARD, useClass: RolesGuard },
  ],
})
export class AuthServiceModule {
  configure(consumer: MiddlewareConsumer) {
    consumer.apply(TenantMiddleware).forRoutes('*');
  }
}
```

## ⚙️ 6) Test with cURL

a) Login → Verify OTP → Get tokens
```bash
# Request OTP
curl -X POST http://localhost:3502/auth/login \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: darmist1" \
  -d '{"usernameOrEmailOrMobile":"testuser","password":"secret123"}' | jq

# Verify OTP (replace loginId + otp)
curl -X POST http://localhost:3502/auth/login/verify \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: darmist1" \
  -d '{"loginId":"a106adcb-7ed5-43a8-beb4-e69cdb26578e","otp":"465841"}' | jq
```

b) List sessions
```bash
curl -X GET http://localhost:3502/auth/sessions \
  -H "Authorization: Bearer <ACCESS_TOKEN>" \
  -H "x-tenant-id: darmist1"
```

```bash
curl -X GET http://localhost:3502/auth/sessions \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI2OTBjMzBmNGIxNmU5NTkxNTgwMWU0ZTUiLCJ0ZW5hbnRJZCI6ImRhcm1pc3QxIiwidXNlcm5hbWUiOiJ0ZXN0dXNlciIsInJvbGUiOiJ1c2VyIiwic2lkIjoiMjIwZTNjNzYtZTVlNi00NTk3LTk1YTgtZDVmNmMxMzYwOWYyIiwiaWF0IjoxNzYyNDIxMTE5LCJleHAiOjE3NjMwMjU5MTl9.o8Wv-8LPqwxTrm_YYlHfWYWh5S8ayhWdu6DR_-Poo58" 
  -H "x-tenant-id: darmist1" | jq
```

Sample Response
```json
{
  "message": "Active login sessions retrieved successfully.",
  "data": [
    {
      "sessionId": "e8c7fa5f-166b-4de2-b2e4-2d290c57cf58",
      "deviceName": "curl/8.7.1",
      "ip": "::1",
      "ua": "curl/8.7.1",
      "refreshHash": "89db5f1237f58a378e726db4de5e548fd052bad967435d3abc0739dd3f28a1a6",
      "createdAt": "2025-11-06T05:26:25.774Z",
      "lastSeen": "2025-11-06T05:26:25.774Z"
    },
    {
      "sessionId": "220e3c76-e5e6-4597-95a8-d5f6c13609f2",
      "deviceName": "curl/8.7.1",
      "ip": "::1",
      "ua": "curl/8.7.1",
      "refreshHash": "fabb9b543254b8f0972bedc76d59da5f364b0995b167eff98862a6a244723b86",
      "createdAt": "2025-11-06T09:25:19.891Z",
      "lastSeen": "2025-11-06T09:25:19.891Z"
    }
  ],
  "meta": {
    "status": "success",
    "code": "SESSIONS_RETRIEVED"
  },
  "ts": "2025-11-06T09:26:45.867Z"
}
```

c) Logout single session
```bash
curl -X POST http://localhost:3502/auth/logout/session \
  -H "Authorization: Bearer <ACCESS_TOKEN>" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: darmist1" \
  -d '{"sessionId":"<SESSION_ID>"}'
```
d) Logout all sessions
```bash
curl -X POST http://localhost:3502/auth/logout/all \
  -H "Authorization: Bearer <ACCESS_TOKEN>" \
  -H "x-tenant-id: darmist1"
```
e) Refresh tokens
```bash
curl -X POST http://localhost:3502/auth/refresh \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: darmist1" \
  -d '{"refreshToken":"<REFRESH_TOKEN>"}'
```

## 🎉 End of Step 8.3

You now have:
*   Sessions are now tracked per user.
*   Refresh uses rotation for maximum security.
*   Roles guard implemented, we will use it in next step.
