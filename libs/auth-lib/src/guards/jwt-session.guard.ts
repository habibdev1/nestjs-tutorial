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
