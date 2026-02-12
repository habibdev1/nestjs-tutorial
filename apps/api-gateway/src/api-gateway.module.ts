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
import { AuthGatewayController } from './auth-gateway.controller';
import { ProductGatewayController } from './product-gateway.controller';

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
  controllers: [
    ApiGatewayController,
    AuthGatewayController,
    TenantGatewayController,
    ProductGatewayController,
  ],
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
