# ✅ Step 8.4 — RBAC and Session Control

## What you’ll have after this step

Auth-gateway configured with global guards:

*   All routes require JWT by default
*   Routes marked `@Public()` bypass JWT
*   Routes marked `@Roles(...)` additionally enforce role checks
*   Gateway session validation (tokens only work while the session exists) via `JwtSessionGuard` and `auth.session.validate` RPC.
*   Public product endpoints: list / get by id / get by slug require no JWT.
*   Per-tenant product DB (no `tenantId` in the product schema).

---

## ⚙️ 1) Auth-Service — add TCP `auth.session.validate`

`apps/auth-service/src/auth-service.service.ts` (add this `validateSession` method)

```typescript
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
      const user = await User.findById(userId).select('-password -sessions.refreshHash');

      if (!user) {
        this.logger.warn(`⚠️ User not found (userId=${userId})`);
        return apiResponse('User not found.', null, {
          status: 'error',
          code: 'USER_NOT_FOUND',
        });
      }

      if (sid) {
        const activeSession = user.sessions?.find((s: any) => s.sessionId === sid);
        if (!activeSession) {
          this.logger.warn(`⚠️ Session not found or expired (sid=${sid})`);
          return apiResponse('Session not found or expired.', null, {
            status: 'error',
            code: 'SESSION_NOT_FOUND',
            sessionId: sid,
          });
        }

        // Optionally check if session is marked "loggedOut" or "disabled"
        if (activeSession.loggedOutAt || activeSession.status === 'LOGGED_OUT') {
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

      this.logger.log(`✅ Token validated (user=${userId}, tenant=${tenantId})`);
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
        return apiResponse(
          'Access token not provided.',
          null,
          { status: 'error', code: 'ACCESS_TOKEN_MISSING' },
        );
      }

      // -------------------- 2. Verify token --------------------
      let payload: any;
      try {
        payload = this.jwt.verify(token);
      } catch (e) {
        return apiResponse(
          'Invalid or expired access token.',
          null,
          { status: 'error', code: 'INVALID_ACCESS_TOKEN' },
        );
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
        return apiResponse(
          'Tenant environment is not initialized.',
          null,
          { status: 'error', code: 'TENANT_CONNECTION_MISSING', details: { tenantId } },
        );
      }

      // -------------------- 4. Load user from DB --------------------
      const User = conn.model('User', UserSchema);
      const user = await User.findById(userId).select('-password -sessions.refreshHash');
      if (!user) {
        return apiResponse(
          'User not found.',
          null,
          { status: 'error', code: 'USER_NOT_FOUND', userId },
        );
      }

      // Optional: if token includes a sessionId, validate it exists
      if (payload.sid) {
        const sessionExists = user.sessions?.some(
          (s: any) => s.sessionId === payload.sid,
        );
        if (!sessionExists) {
          return apiResponse(
            'Session not found or expired.',
            null,
            { status: 'error', code: 'SESSION_NOT_FOUND', sessionId: payload.sid },
          );
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

      return apiResponse(
        'Current user retrieved successfully.',
        safeUser,
        { status: 'success', code: 'CURRENT_USER_OK' },
      );
    } catch (err: any) {
      this.logger.error('❌ Error in getCurrentUserFromAccessToken', err.stack || err);
      return apiResponse(
        'Failed to retrieve current user from token.',
        null,
        { status: 'error', code: 'INTERNAL_ERROR', error: err.message },
      );
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
      if (!/\s/.test(auth)) return auth; // raw token (no "Bearer ")
    }

    const xToken = req.headers?.['x-access-token'];
    if (xToken && typeof xToken === 'string') return xToken.trim();

    const cookies = req.cookies || {};
    if (cookies.AccessToken) return String(cookies.AccessToken);
    if (cookies.authorization) return String(cookies.authorization);

    return null;
  }
```

`apps/auth-service/src/auth-service.controller.ts`

```typescript
 // ───────────────────────────────
  // TCP: Validate Access Token
  // ───────────────────────────────
  @MessagePattern({ cmd: 'auth.session.validate' })
  async validateAccessTokenTcp(
    @Payload()
    payload: {
      req?: any;
      tenantId: string;
      ip?: string;
      'user-agent'?: string;
      token?: string;
    },
  ) {
    const conn = await this.databaseLibService.getTenantConnection(
      payload.tenantId,
    );

    const req = {
      tenantId: payload.tenantId,
      tenantConnection: conn,
      headers: {
        authorization: payload.token
          ? `Bearer ${payload.token}`
          : payload?.req?.headers?.authorization,
        'x-tenant-id': payload.tenantId,
        'user-agent': payload['user-agent'] || 'tcp-client',
      },
      cookies: payload?.req?.cookies || {},
      ip: payload.ip || '0.0.0.0',
    };

    const result = await this.service.validateSession(req);
    return result;
  }

  // ───────────────────────────────
  // TCP: Get current user details
  // ───────────────────────────────
  @MessagePattern({ cmd: 'auth.get-current-user' })
  async getCurrentUserTcp(
    @Payload()
    payload: {
      token: string;
      tenantId: string;
      'user-agent'?: string;
      ip?: string;
    },
  ) {
    const conn = await this.databaseLibService.getTenantConnection(
      payload.tenantId,
    );

    const fakeReq = {
      tenantId: payload.tenantId,
      tenantConnection: conn,
      headers: {
        authorization: `Bearer ${payload.token}`,
        'user-agent': payload['user-agent'] || 'tcp-client',
      },
      ip: payload.ip || '0.0.0.0',
    };

    const result = await this.service.getCurrentUserFromAccessToken(fakeReq);
    return result;
  }

  // ───────────────────────────────
  // TCP: Change User Role
  // ───────────────────────────────
  @MessagePattern({ cmd: 'auth.changeUserRole' })
  async changeUserRoleTcp(
    @Payload() payload: { tenantId: string; userId: string; newRole: string },
  ) {
    const conn = await this.databaseLibService.getTenantConnection(
      payload.tenantId,
    );
    const req = {
      tenantId: payload.tenantId,
      tenantConnection: conn,
      headers: { 'user-agent': payload['user-agent'] || 'tcp-client' },
      ip: '0.0.0.0',
    };
    const result = await this.service.changeUserRole(req, {
      userId: payload.userId,
      newRole: payload.newRole,
    });
    return result;
  }
```

---

## ⚙️ 2) JwtSessionGuard

We’ll add `JwtSessionGuard` here and wire it in the gateway. Place this into your `libs/auth-lib` package and export it from the lib’s `index.ts`.

`libs/auth-lib/src/guards/jwt-session.guard.ts`

```typescript
import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
  Inject,
  Logger,
} from '@nestjs/common';
import { ClientProxy } from '@nestjs/microservices';
import { firstValueFrom } from 'rxjs';
import { Reflector } from '@nestjs/core';
import { IS_PUBLIC_KEY } from '../decorators/public.decorator';

@Injectable()
export class JwtSessionGuard implements CanActivate {
  private readonly logger = new Logger(JwtSessionGuard.name);

  constructor(
    private readonly reflector: Reflector,
    @Inject('AUTH_SERVICE') private readonly authClient: ClientProxy,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    if (context.getType() !== 'http') return true;

    const isPublic = this.reflector.getAllAndOverride<boolean>(IS_PUBLIC_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);
    if (isPublic) return true;

    const req = context.switchToHttp().getRequest();
    const payload = req.user;

    const authHeader = req.headers?.authorization || req.headers?.Authorization;
    let token: string | null = null;

    if (authHeader && typeof authHeader === 'string') {
      const [scheme, value] = authHeader.trim().split(/\s+/);
      if (/^Bearer$/i.test(scheme) && value) token = value;
      else if (!/\s/.test(authHeader)) token = authHeader; // raw token (no "Bearer ")
    }

    if (!payload) throw new UnauthorizedException('Missing JWT payload');

    const tenantId = req.headers['x-tenant-id'] as string;
    const { sub: userId, sid, username } = payload || {};

    if (!tenantId || !userId || !sid)
      throw new UnauthorizedException('Invalid or malformed token payload');

    // 🔐 Validate live session via auth-service microservice
    try {
      const result = await firstValueFrom(
        this.authClient.send(
          { cmd: 'auth.session.validate' },
          { token, tenantId, userId, sid },
        ),
      );

      if (
        !result ||
        result?.meta?.code !== 'ACCESS_TOKEN_VALID' ||
        (result.data.id !== userId && result.data.sessionId !== sid)
      ) {
        this.logger.warn(
          `Session expired or revoked (user=${userId}, sid=${sid})`,
        );
        throw new UnauthorizedException('Session expired or revoked');
      }

      // Attach normalized actor info for downstream services
      req.actor = { id: userId, username: username ?? result.username };
      return true;
    } catch (err) {
      this.logger.error(`❌ Session validation failed`, err);
      throw new UnauthorizedException('Session validation failed');
    }
  }
}
```

`libs/auth-lib/src/index.ts` (ensure exports)

```typescript
export * from './guards/jwt-session.guard';
```

---

## ⚙️ 3) API-Gateway — register global guards & ensure AUTH_SERVICE client

Order matters: `JwtAuthGuard` → `JwtSessionGuard` → `RolesGuard`.

`apps/api-gateway/src/api-gateway.module.ts`

```typescript
import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { ClientsModule, Transport } from '@nestjs/microservices';
import { ApiGatewayController } from './api-gateway.controller';
import { ApiGatewayService } from './api-gateway.service';
import { TenantGatewayController } from './tenant-gateway.controller';
import {
  JwtStrategy,
  JwtAuthGuard,
  RolesGuard,
  JwtSessionGuard,
} from '@app/auth-lib';
import { PassportModule } from '@nestjs/passport';
import { JwtModule } from '@nestjs/jwt';
import { APP_GUARD } from '@nestjs/core';

@Module({
  imports: [
    ConfigModule.forRoot({ isGlobal: true }),
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
    ClientsModule.registerAsync([
      {
        name: 'AUTH_SERVICE',
        imports: [ConfigModule],
        inject: [ConfigService],
        useFactory: (cfg: ConfigService) => ({
          transport: Transport.TCP,
          options: {
            host: '0.0.0.0',
            port: Number(cfg.get('AUTH_SERVICE_TCP_PORT') || 4502),
          },
        }),
      },
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
      {
        name: 'USER_SERVICE',
        imports: [ConfigModule],
        inject: [ConfigService],
        useFactory: (cfg: ConfigService) => ({
          transport: Transport.TCP,
          options: {
            host: '0.0.0.0',
            port: Number(cfg.get('USER_SERVICE_TCP_PORT') || 4504),
          },
        }),
      },
      {
        name: 'PRODUCT_SERVICE',
        imports: [ConfigModule],
        inject: [ConfigService],
        useFactory: (configService: ConfigService) => ({
          transport: Transport.TCP,
          options: {
            host: '0.0.0.0',
            port: Number(configService.get('PRODUCT_SERVICE_TCP_PORT') || 4505),
          },
        }),
      },
    ]),
  ],
  controllers: [ApiGatewayController, TenantGatewayController],
  providers: [
    ApiGatewayService,
    JwtStrategy,
    // Global guards: order matters (JWT first, then Session, then Roles)
    { provide: APP_GUARD, useClass: JwtAuthGuard },
    { provide: APP_GUARD, useClass: JwtSessionGuard },
    { provide: APP_GUARD, useClass: RolesGuard },
  ],
})
export class ApiGatewayModule {}
```

Using `APP_GUARD` means you don’t need to put `@UseGuards(JwtAuthGuard, RolesGuard)` on every controller. Just add `@Public()` where you want a route open, and `@Roles(...)` where you want role checks.

---

## ⚙️ 4) Auth-Gateway-Controller — full file (RBAC + Public + actor)

We’ll register global guards so every controller benefits automatically:

*   `JwtAuthGuard` (global): protects all routes unless `@Public()`
*   `RolesGuard` (global): checks roles when `@Roles()` is present

`apps/api-gateway/src/auth-gateway.controller.ts`

```typescript
// apps/api-gateway/src/controllers/auth-gateway.controller.ts

import {
  BadRequestException,
  Body,
  Controller,
  Get,
  Headers,
  Inject,
  Post,
  Query,
  Req,
  UseGuards,
} from '@nestjs/common';
import { ClientProxy } from '@nestjs/microservices';
import { firstValueFrom, timeout, catchError, throwError } from 'rxjs';
import { SignupDto } from '../../auth-service/src/dto/signup.dto';
import { LoginDto } from '../../auth-service/src/dto/login.dto';
import { VerifyOtpDto } from '../../auth-service/src/dto/verify-otp.dto';
import { JwtAuthGuard, JwtSessionGuard, Public, Roles } from '@app/auth-lib';
import { LogoutSessionDto } from '../../auth-service/src/dto/logout-session.dto';
import { RefreshDto } from '../../auth-service/src/dto/refresh.dto';

@Controller('gateway/auth')
export class AuthGatewayController {
  constructor(
    @Inject('AUTH_SERVICE') private readonly authClient: ClientProxy,
  ) {}

  private async sendSafe<T>(cmd: string, payload: any): Promise<T> {
    try {
      return await firstValueFrom(
        this.authClient.send<T>({ cmd }, payload).pipe(
          timeout(10000),
          catchError((error) => {
            const message =
              error?.message ||
              error?.response?.message ||
              'Auth service error';
            const errors = error?.response?.errors;
            return throwError(
              () => new BadRequestException({ message, errors }),
            );
          }),
        ),
      );
    } catch (unexpected: any) {
      throw new BadRequestException(
        unexpected?.response || {
          message: unexpected?.message || 'Auth service error',
        },
      );
    }
  }

  // ───────────────────────────────
  // Signup
  // ───────────────────────────────
  @Public()
  @Post('signup')
  async signup(
    @Headers('x-tenant-id') tenantId: string,
    @Body() dto: SignupDto,
  ) {
    if (!tenantId) throw new BadRequestException('x-tenant-id is required');
    const result = await this.sendSafe<any>('auth.signup', {
      ...dto,
      tenantId,
    });
    return result;
  }

  // ───────────────────────────────
  // Login (send OTP)
  // ───────────────────────────────
  @Public()
  @Post('login')
  async login(@Headers('x-tenant-id') tenantId: string, @Body() dto: LoginDto) {
    if (!tenantId) throw new BadRequestException('x-tenant-id is required');
    const result = await this.sendSafe<any>('auth.login', { ...dto, tenantId });
    return result;
  }

  // ───────────────────────────────
  // Verify OTP → Tokens
  // ───────────────────────────────
  @Public()
  @Post('login/verify')
  async verifyOtp(
    @Headers('x-tenant-id') tenantId: string,
    @Body() dto: VerifyOtpDto,
  ) {
    if (!tenantId) throw new BadRequestException('x-tenant-id is required');
    const result = await this.sendSafe<any>('auth.verifyOtp', {
      ...dto,
      tenantId,
    });
    return result;
  }

  // ───────────────────────────────
  // Unlock account
  // ───────────────────────────────
  @Public()
  @Get('unlock')
  async unlock(
    @Headers('x-tenant-id') tenantId: string,
    @Query('token') token: string,
  ) {
    if (!tenantId) throw new BadRequestException('x-tenant-id is required');
    const result = await this.sendSafe<any>('auth.unlock', { tenantId, token });
    return result;
  }

  // ───────────────────────────────
  // List sessions
  // ───────────────────────────────
  @UseGuards(JwtAuthGuard, JwtSessionGuard)
  @Get('sessions')
  async sessions(@Headers('x-tenant-id') tenantId: string, @Req() req: any) {
    if (!tenantId) throw new BadRequestException('x-tenant-id is required');
    const safeReq = {
      user: req.user,
      headers: { 'user-agent': req.headers['user-agent'] || 'unknown' },
      ip: req.ip || req.connection?.remoteAddress || '0.0.0.0',
    };
    const result = await this.sendSafe<any>('auth.sessions', {
      tenantId,
      req: safeReq,
    });
    return result;
  }

  // ───────────────────────────────
  // Logout single session
  // ───────────────────────────────
  @UseGuards(JwtAuthGuard, JwtSessionGuard)
  @Post('logout/session')
  async logoutSession(
    @Headers('x-tenant-id') tenantId: string,
    @Req() req: any,
    @Body() dto: LogoutSessionDto,
  ) {
    if (!tenantId) throw new BadRequestException('x-tenant-id is required');
    const safeReq = {
      user: req.user,
      headers: { 'user-agent': req.headers['user-agent'] },
      ip: req.ip || req.connection?.remoteAddress || '0.0.0.0',
    };
    const result = await this.sendSafe<any>('auth.logoutSession', {
      tenantId,
      req: safeReq,
      sessionId: dto.sessionId,
    });
    return result;
  }

  // ───────────────────────────────
  // Logout all sessions
  // ───────────────────────────────
  @UseGuards(JwtAuthGuard, JwtSessionGuard)
  @Post('logout/all')
  async logoutAll(@Headers('x-tenant-id') tenantId: string, @Req() req: any) {
    if (!tenantId) throw new BadRequestException('x-tenant-id is required');
    const safeReq = {
      user: req.user,
      headers: { 'user-agent': req.headers['user-agent'] },
      ip: req.ip || req.connection?.remoteAddress || '0.0.0.0',
    };
    const result = await this.sendSafe<any>('auth.logoutAll', {
      tenantId,
      req: safeReq,
    });
    return result;
  }

  // ───────────────────────────────
  // Refresh tokens
  // ───────────────────────────────
  @UseGuards(JwtAuthGuard, JwtSessionGuard)
  @Post('refresh')
  async refresh(
    @Headers('x-tenant-id') tenantId: string,
    @Req() req: any,
    @Body() dto: RefreshDto,
  ) {
    if (!tenantId) throw new BadRequestException('x-tenant-id is required');
    const safeReq = {
      user: req.user,
      headers: { 'user-agent': req.headers['user-agent'] },
      ip: req.ip || req.connection?.remoteAddress || '0.0.0.0',
    };
    const result = await this.sendSafe<any>('auth.refresh', {
      tenantId,
      req: safeReq,
      refreshToken: dto.refreshToken,
    });
    return result;
  }

  // ───────────────────────────────
  // Change role
  // ───────────────────────────────
  @Roles('admin')
  @Post('change-role')
  async changeUserRole(
    @Headers('x-tenant-id') tenantId: string,
    @Body('userId') userId: string,
    @Body('newRole') newRole: string,
  ) {
    if (!tenantId) throw new BadRequestException('x-tenant-id is required');
    const result = await this.sendSafe<any>('auth.changeUserRole', {
      tenantId,
      userId,
      newRole,
    });
    return result;
  }

  // ───────────────────────────────
  // Get Current User (from Access Token)
  // ───────────────────────────────
  @UseGuards(JwtAuthGuard)
  @Get('me')
  async getCurrentUser(
    @Headers('x-tenant-id') tenantId: string,
    @Req() req: any,
  ) {
    if (!tenantId) throw new BadRequestException('x-tenant-id is required');

    const accessToken =
      req.headers['authorization'] || req.headers['Authorization'];
    if (!accessToken) {
      throw new BadRequestException('Authorization header is required');
    }

    const token = accessToken.replace(/^Bearer\s+/i, '');

    const result = await this.sendSafe<any>('auth.get-current-user', {
      tenantId,
      token,
      'user-agent': req.headers['user-agent'],
      ip: req.ip || req.connection?.remoteAddress || '0.0.0.0',
    });

    return result;
  }
}
```

Update `api-gateway.module` to include all api endpoints from `AuthGatewayController`.

`apps/api-gateway/src/api-gateway.module.ts`

```typescript
 controllers: [
    ApiGatewayController,
    AuthGatewayController,
    TenantGatewayController,
  ],
```

---

## ⚙️ 5) cURL Tests

### a) Signup

```bash
curl -X POST http://localhost:3501/gateway/auth/signup \
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

Expected (201):

```json
{
  "message": "Signup successful. Please verify your account if required.",
  "data": {
    "id": "690c30f4b16e95915801e4e5",
    "username": "testuser",
    "email": "testuser@darmist.com",
    "role": "user"
  },
  "meta": {
    "status": "success",
    "code": "SIGNUP_SUCCESS"
  },
  "ts": "2025-11-06T05:20:12.814Z"
}
```

### b) Request OTP (Login)

```bash
curl -X POST http://localhost:3501/gateway/auth/login \
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

### c) Verify OTP → Get Tokens

```bash
curl -X POST http://localhost:3501/gateway/auth/login/verify \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: darmist1" \
  -d '{
    "loginId": "c1e0d2ba-237e-47e1-b18b-d86a092c4058",
    "otp": "903335"
  }' | jq
```

Expected (200):

```json
{
  "message": "You have successfully logged in to DARMIST Lab.",
  "data": {
    "accessToken": "<ACCESS_TOKEN>",
    "refreshToken": "<REFRESH_TOKEN>",
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

### d) Get Current User

```bash
curl http://localhost:3501/gateway/auth/me \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: darmist1" \
  -H "Authorization: Bearer <ACCESS_TOKEN>" | jq
```

Expected (200):

```json
{
  "message": "Authenticated user retrieved successfully.",
  "data": {
    "id": "690c30f4b16e95915801e4e5",
    "username": "testuser",
    "email": "testuser@darmist.com",
    "role": "user",
    "sessionId": "e8c7fa5f-166b-4de2-b2e4-2d290c57cf58"
  },
  "meta": {
    "status": "success",
    "code": "USER_INFO"
  },
  "ts": "2025-11-06T05:35:22.890Z"
}
```

### e) List Active Sessions

```bash
curl http://localhost:3501/gateway/auth/sessions \
  -H "x-tenant-id: darmist1" \
  -H "Authorization: Bearer <ACCESS_TOKEN>" | jq
```

Expected (200):

```json
{
  "message": "Active sessions retrieved successfully.",
  "data": [
    {
      "sessionId": "e8c7fa5f-166b-4de2-b2e4-2d290c57cf58",
      "device": "Chrome on macOS",
      "ip": "127.0.0.1",
      "current": true,
      "lastActive": "2025-11-06T05:35:10.002Z"
    }
  ],
  "meta": {
    "status": "success",
    "code": "SESSIONS_LISTED"
  },
  "ts": "2025-11-06T05:37:48.444Z"
}
```

### f) Logout a Single Session

```bash
curl -X POST http://localhost:3501/gateway/auth/logout/session \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: darmist1" \
  -H "Authorization: Bearer <ACCESS_TOKEN>" \
  -d '{"sessionId":"e8c7fa5f-166b-4de2-b2e4-2d290c57cf58"}' | jq
```

Expected (200):

```json
{
  "message": "The selected session has been successfully logged out.",
  "meta": {
    "status": "success",
    "code": "LOGOUT_SESSION_SUCCESS"
  },
  "ts": "2025-11-06T05:39:12.771Z"
}
```

### g) Logout All Sessions

```bash
curl -X POST http://localhost:3501/gateway/auth/logout/all \
  -H "x-tenant-id: darmist1" \
  -H "Authorization: Bearer <ACCESS_TOKEN>" | jq
```

Expected (200):

```json
{
  "message": "All sessions have been successfully terminated.",
  "meta": {
    "status": "success",
    "code": "LOGOUT_ALL_SUCCESS"
  },
  "ts": "2025-11-06T05:40:05.621Z"
}
```

🔒 After this, retrying `/gateway/auth/me` should yield:

```json
{
  "message": "Session expired or revoked.",
  "meta": {
    "status": "error",
    "code": "SESSION_EXPIRED"
  }
}
```

### h) Refresh Tokens

```bash
curl -X POST http://localhost:3501/gateway/auth/refresh \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: darmist1" \
  -H "Authorization: Bearer <ACCESS_TOKEN>" \
  -d '{"refreshToken":"<REFRESH_TOKEN>"}' | jq
```

Expected (200):

```json
{
  "message": "Access token refreshed successfully.",
  "data": {
    "accessToken": "<NEW_ACCESS_TOKEN>",
    "refreshToken": "<NEW_REFRESH_TOKEN>"
  },
  "meta": {
    "status": "success",
    "code": "TOKEN_REFRESHED"
  },
  "ts": "2025-11-06T05:42:11.508Z"
}
```

### i) 🔴 Change User Role (Admin Only)

```bash
curl -X POST http://localhost:3501/gateway/auth/change-role \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: darmist1" \
  -H "Authorization: Bearer <ADMIN_ACCESS_TOKEN>" \
  -d '{
    "userId": "690c30f4b16e95915801e4e5",
    "newRole": "admin"
  }' | jq
```

Expected (200):

```json
{
  "message": "User role has been updated successfully.",
  "data": {
    "id": "690c30f4b16e95915801e4e5",
    "username": "testuser",
    "email": "testuser@darmist.com",
    "previousRole": "user",
    "newRole": "admin"
  },
  "meta": {
    "status": "success",
    "code": "USER_ROLE_UPDATED"
  },
  "ts": "2025-11-06T11:33:24.431Z"
}
```

Expected (403) if non-admin:

```json
{
  "message": "Forbidden resource. Admin privileges required.",
  "meta": {
    "status": "error",
    "code": "FORBIDDEN"
  },
  "ts": "2025-11-06T05:46:11.233Z"
}

```