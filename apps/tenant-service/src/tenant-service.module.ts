import { Module } from '@nestjs/common';
import { TenantServiceController } from './tenant-service.controller';
import { TenantServiceService } from './tenant-service.service';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { MongooseModule } from '@nestjs/mongoose';
import { Tenant, TenantSchema } from './schemas/tenant.schema';
import { RedisLibModule } from '@app/redis-lib';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true, // Makes env available everywhere
    }),

    // DB connection
    MongooseModule.forRootAsync({
      useFactory: (cfg: ConfigService) => ({
        uri: cfg.get<string>('MONGO_URI_TENANT'),
      }),
      inject: [ConfigService],
    }),

    // Register Tenant schema
    MongooseModule.forFeature([{ name: Tenant.name, schema: TenantSchema }]),

    // Redis Caching
    RedisLibModule,
  ],
  controllers: [TenantServiceController],
  providers: [TenantServiceService],
})
export class TenantServiceModule {}
