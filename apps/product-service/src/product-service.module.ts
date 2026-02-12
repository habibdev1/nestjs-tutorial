import { Module, MiddlewareConsumer } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { ClientsModule, Transport } from '@nestjs/microservices';
import { ProductServiceController } from './product-service.controller';
import { ProductServiceService } from './product-service.service';
import { DatabaseLibService } from '@app/database-lib';
import { RedisLibModule } from '@app/redis-lib';
import { TenantMiddleware } from '@app/database-lib/tenant.middleware';

@Module({
  imports: [
    ConfigModule.forRoot({ isGlobal: true }),
    RedisLibModule,
    // If product-service needs to call auth-service, tenant-service itself (optional here)
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
        useFactory: (configService: ConfigService) => ({
          transport: Transport.TCP,
          options: {
            host: '0.0.0.0',
            port: configService.get<number>('TENANT_SERVICE_TCP_PORT', 4503),
          },
        }),
      },
    ]),
  ],
  controllers: [ProductServiceController],
  providers: [
    DatabaseLibService, // exposes helpers TenantMiddleware depends on
    ProductServiceService,
  ],
})
export class ProductServiceModule {
  configure(consumer: MiddlewareConsumer) {
    // 👇 Attach per-tenant DB connection for HTTP paths
    consumer.apply(TenantMiddleware).forRoutes('*');
  }
}
