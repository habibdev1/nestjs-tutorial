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
  async signupTcp(@Payload() payload: any & { tenantId: string }) {
    const conn = await this.databaseLibService.getTenantConnection(
      payload.tenantId,
    );

    const saved = await this.service.signup(
      {
        tenantId: payload.tenantId,
        tenantConnection: conn,
        headers: payload?.req?.headers,
      },
      payload,
    );
    return saved;
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
  async loginTcp(@Payload() payload: any & { tenantConnection?: any }) {
    const conn = await this.databaseLibService.getTenantConnection(
      payload.tenantId,
    );

    const req = {
      tenantId: payload.tenantId,
      tenantConnection: conn,
      headers: payload?.req?.headers,
    };

    const result = await this.service.login(req, payload);
    return result;
  }

  // ───────────────────────────────
  // TCP Endpoint: Login → Verify OTP
  // ───────────────────────────────
  @MessagePattern({ cmd: 'auth.verifyOtp' })
  async verifyOtpTcp(@Payload() payload: any & { tenantConnection?: any }) {
    const conn = await this.databaseLibService.getTenantConnection(
      payload.tenantId,
    );

    const req = {
      tenantId: payload.tenantId,
      tenantConnection: conn,
      headers: payload?.req?.headers,
    };

    const result = await this.service.verifyOtp(req, payload);
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
      headers: payload?.req?.headers,
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
    },
  ) {
    const conn = await this.databaseLibService.getTenantConnection(
      payload.tenantId,
    );
    const req = {
      tenantId: payload.tenantId,
      tenantConnection: conn,
      user: payload?.req?.user,
      headers: payload?.req?.headers,
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
    },
  ) {
    const conn = await this.databaseLibService.getTenantConnection(
      payload.tenantId,
    );
    const req = {
      tenantId: payload.tenantId,
      tenantConnection: conn,
      user: payload?.req?.user,
      headers: payload?.req?.headers,
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
      req?: any;
    },
  ) {
    const conn = await this.databaseLibService.getTenantConnection(
      payload.tenantId,
    );
    const req = {
      tenantId: payload.tenantId,
      tenantConnection: conn,
      user: payload.user,
      headers: payload?.req?.headers,
    };
    const result = await this.service.refresh(req, payload.refreshToken);
    return result;
  }

  // ───────────────────────────────
  // TCP: Validate Access Token
  // ───────────────────────────────
  @MessagePattern({ cmd: 'auth.session.validate' })
  async validateAccessTokenTcp(
    @Payload()
    payload: {
      req?: any;
      tenantId: string;
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
      },
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
      req: any;
    },
  ) {
    const conn = await this.databaseLibService.getTenantConnection(
      payload.tenantId,
    );

    const fakeReq = {
      tenantId: payload.tenantId,
      tenantConnection: conn,
      headers: {
        ...payload?.req?.headers,
        authorization: `Bearer ${payload.token}`,
      },
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
}
