# ✅ Step 6 — Multi-Tenancy (Auth Service Example)

## 🎯 Goal

*   Enable per-tenant MongoDB databases (e.g., `darmist_darmist1`, `darmist_darmist2`).
*   Identify tenants by `x-tenant-id` header.
*   Validate tenants via tenant-service (TCP) with Redis caching.
*   Use `DatabaseLibService` from `@app/database-lib` for tenant DB connections.
*   Attach tenant connection to `req.tenantConnection`.
*   Show a dummy User schema in auth-service as a working test.

## ⚙️ 1) DatabaseLibService (per-tenant DB manager)

**File:** `libs/database-lib/src/database-lib.service.ts`
```typescript
import {
  Injectable,
  Logger,
  InternalServerErrorException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import mongoose, { Connection, ConnectOptions } from 'mongoose';

/**
 * DatabaseLibService
 * ------------------
 * - Manages per-tenant MongoDB connections.
 * - Each tenant gets a dedicated DB: {MONGO_DB_PREFIX}_{tenantName}.
 * - Connections are cached for reuse.
 */
@Injectable()
export class DatabaseLibService {
  private readonly logger = new Logger(DatabaseLibService.name);
  private readonly connections = new Map<string, Connection>();

  constructor(private readonly config: ConfigService) {}

  /**
   * Get or create a tenant-specific MongoDB connection.
   * @param tenantName Unique tenant identifier (from x-tenant-id header)
   */
  async getTenantConnection(tenantName: string): Promise<Connection> {
    if (!tenantName) {
      throw new InternalServerErrorException(
        'Missing tenantName for DB connection',
      );
    }

    // ✅ Return cached connection if it already exists
    if (this.connections.has(tenantName)) {
      return this.connections.get(tenantName)!;
    }

    // 🔗 Build tenant-specific DB URI
    const baseUri = this.config
      .get<string>('MONGO_URI', 'mongodb://localhost:27017')
      .replace(///$/, '');
    const prefix = this.config.get<string>('MONGO_DB_PREFIX', 'aerostitch');
    const dbName = `${prefix}_${tenantName}`;
    const uri = `${baseUri}/${dbName}`;

    const options: ConnectOptions = {
      autoCreate: true,
      retryWrites: true,
      w: 'majority',
    };

    this.logger.log(`🔌 Connecting to tenant DB "${dbName}" at ${uri}`);

    try {
      const conn = await mongoose.createConnection(uri, options).asPromise();
      this.connections.set(tenantName, conn);

      // Observability logs
      conn.on('connected',
        () =>
          this.logger.log(`✅ Tenant DB connected: ${tenantName}`),
      );
      conn.on('error', (err) =>
        this.logger.error(`❌ Tenant DB error (${tenantName}): ${err.message}`),
      );
      conn.on('disconnected',
        () =>
          this.logger.warn(`⚠️ Tenant DB disconnected: ${tenantName}`),
      );

      return conn;
    } catch (err) {
      this.logger.error(
        `Failed to connect DB (tenant=${tenantName})`,
        err.stack,
      );
      throw new InternalServerErrorException(
        `Database connection failed for tenant "${tenantName}"`,
      );
    }
  }
}
```

👉 Note: We import this service with
```typescript
import { DatabaseLibService } from '@app/database-lib';
```

## ⚙️ 2) Tenant Middleware (validate tenant + attach connection)

**File:** `libs/database-lib/src/tenant.middleware.ts`
```typescript
import {
  Injectable,
  NestMiddleware,
  BadRequestException,
  ForbiddenException,
  Inject,
  Logger,
} from '@nestjs/common';
import { Request, Response, NextFunction } from 'express';
import { DatabaseLibService } from '@app/database-lib';
import { ClientProxy } from '@nestjs/microservices';
import { lastValueFrom, TimeoutError } from 'rxjs';
import { RedisLibService } from '@app/redis-lib';

/**
 * TenantMiddleware
 * ----------------
 * - Extracts tenant name from request header.
 * - Validates tenant via tenant-service (TCP).
 * - Caches tenant validation in Redis.
 * - Ensures tenant is ACTIVE before proceeding.
 * - Attaches tenantConnection to request object.
 */
@Injectable()
export class TenantMiddleware implements NestMiddleware {
  private readonly logger = new Logger(TenantMiddleware.name);

  constructor(
    private readonly dbService: DatabaseLibService,
    @Inject('TENANT_SERVICE') private readonly tenantClient: ClientProxy,
    private readonly cache: RedisLibService,
  ) {}

  async use(req: Request, _res: Response, next: NextFunction) {
    const tenantName = (req.headers['x-tenant-id'] as string)?.trim();
    if (!tenantName) {
      throw new BadRequestException(`Missing 'x-tenant-id' header`);
    }

    // 1️⃣ Try Redis cache first
    let tenantRecord: any = await this.cache.get(`tenant:${tenantName}`);

    // 2️⃣ Fallback to tenant-service (TCP)
    if (!tenantRecord) {
      try {
        await this.tenantClient.connect();
        tenantRecord = await lastValueFrom(
          this.tenantClient.send({ cmd: 'tenant.findByName' }, tenantName),
        );
        if (tenantRecord?.data) {
          tenantRecord = tenantRecord.data;
          await this.cache.set(`tenant:${tenantName}`, tenantRecord, 300);
        }
      } catch (err) {
        if (err instanceof TimeoutError) {
          throw new BadRequestException(`Tenant validation timed out`);
        }
        throw new BadRequestException(`Tenant "${tenantName}" not found`);
      }
    }

    if (!tenantRecord) {
      throw new BadRequestException(`Tenant "${tenantName}" not found`);
    }

    // 3️⃣ Enforce ACTIVE tenants only
    if (tenantRecord.status !== 'ACTIVE') {
      throw new ForbiddenException(`Tenant "${tenantName}" is not active`);
    }

    // 4️⃣ Attach tenant-specific DB connection
    const connection = await this.dbService.getTenantConnection(tenantName);
    (req as any).tenantConnection = connection;

    this.logger.debug(`➡️ TenantMiddleware passed (${tenantName})`);
    next();
  }
}
```

## ⚙️ 3) Apply Middleware in Auth Service

**File:** `apps/auth-service/src/auth-service.module.ts`
```typescript
import { Module, MiddlewareConsumer } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { ClientsModule, Transport } from '@nestjs/microservices';
import { RedisLibModule } from '@app/redis-lib';
import { DatabaseLibService } from '@app/database-lib';
import { TenantMiddleware } from '@app/database-lib/tenant.middleware';
import { AuthTestController } from './auth-test.controller';

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
  controllers: [AuthTestController],
  providers: [DatabaseLibService],
})
export class AuthServiceModule {
  configure(consumer: MiddlewareConsumer) {
    consumer.apply(TenantMiddleware).forRoutes('*');
  }
}
```

## ⚙️ 4) Test Controller (Dummy User Model)

**File:** `apps/auth-service/src/auth-test.controller.ts`
```typescript
import { Controller, Get, Post, Body, Req } from '@nestjs/common';
import { Schema } from 'mongoose';
import { apiResponse } from '@app/common-lib';

// Define a simple User schema
const UserSchema = new Schema(
  {
    username: { type: String, required: true },
    email: { type: String, required: true },
  },
  { timestamps: true },
);

@Controller('auth-test')
export class AuthTestController {
  @Post()
  async create(@Req() req: any, @Body() body: any) {
    const conn = req.tenantConnection;
    const User = conn.model('User', UserSchema);
    const created = await new User(body).save();
    return apiResponse('User created (tenant scoped)', created);
  }

  @Get()
  async findAll(@Req() req: any) {
    const conn = req.tenantConnection;
    const User = conn.model('User', UserSchema);
    const users = await User.find().lean().exec();
    return apiResponse('Users list (tenant scoped)', users);
  }
}
```

## ⚙️ 5) Verify Multi-Tenant Auth Service

Start tenant-service + auth-service:
```bash
npx nest start tenant-service --watch
npx nest start auth-service --watch
```

Create two tenants (`darmist1` & `darmist2`) via tenant-service and set status to ACTIVE.

Change tenant status by name
```bash
curl -X PATCH http://localhost:3501/gateway/tenants/by-name/darmist1/status \
  -H "Content-Type: application/json" \
  -d '{
    "status": "ACTIVE"
  }'
```

Add users in tenant `darmist1`:
```bash
curl -X POST http://localhost:3502/auth-test \
  -H "x-tenant-id: darmist1" \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","email":"alice@darmist1.com"}'
```

Add users in tenant `darmist2`:
```bash
curl -X POST http://localhost:3502/auth-test \
  -H "x-tenant-id: darmist2" \
  -H "Content-Type: application/json" \
  -d '{"username":"bob","email":"bob@darmist2.com"}'
```

Fetch lists separately:
```bash
curl http://localhost:3502/auth-test -H "x-tenant-id: darmist1"
curl http://localhost:3502/auth-test -H "x-tenant-id: darmist2"
```
✅ Each tenant sees only their own users, stored in separate DBs (`darmist_darmist1`, `darmist_darmist2`).

## 🎉 End of Step 6

*   `DatabaseLibService` (`@app/database-lib`) manages tenant DBs.
*   `TenantMiddleware` validates tenants via tenant-service (TCP) + Redis cache.
*   Ensures only ACTIVE tenants can access.
*   Auth-service test shows real tenant-scoped data isolation.
