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
