# ✅ Step 2: Environment Setup

## ⚙️ 1. Install Config Module

Install the config module:
```bash
npm install @nestjs/config
```
This allows us to load environment variables globally.

## ⚙️ 2. Create .env File at Root

We’ll define all important variables in advance so we don’t have to keep editing later.

**File:** `.env`
```dotenv
# ── General Environment ───────────────────────────────
NODE_ENV=development
APP_NAME=nestjs-tutorial
APP_BASE_URL=https://nestjs-tutorial.darmist.com

# ── API Gateway (HTTP only) ───────────────────────────
API_GATEWAY_HTTP_PORT=3501

# ── Auth Service ──────────────────────────────────────
AUTH_SERVICE_HTTP_PORT=3502
AUTH_SERVICE_TCP_PORT=4502

# ── Tenant Service ────────────────────────────────────
TENANT_SERVICE_HTTP_PORT=3503
TENANT_SERVICE_TCP_PORT=4503

# ── User Service ──────────────────────────────────────
USER_SERVICE_HTTP_PORT=3504
USER_SERVICE_TCP_PORT=4504

# ── Product Service ───────────────────────────────────
PRODUCT_SERVICE_HTTP_PORT=3505
PRODUCT_SERVICE_TCP_PORT=4505

# ── Database (MongoDB) ────────────────────────────────
MONGO_URI=mongodb://localhost:27017
MONGO_URI_TENANT=mongodb://localhost:27017/nestjs_tutorial_tenant_db
MONGO_DB_PREFIX=nestjs_tutorial
MONGO_USER=
MONGO_PASSWORD=
MONGO_AUTH_DB=admin
MONGO_SSL=false

# ── Redis ─────────────────────────────────────────────
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_USER=nestjs_tutorial
REDIS_PASSWORD="YourSecreetPassword@2025"
REDIS_PREFIX=nestjs_tutorial:

# ── Security (JWT) ────────────────────────────────────
JWT_SECRET=AeroStitch@2000
PASSWORD_SALT_ROUNDS=10
JWT_EXPIRES_IN=7d
JWT_REFRESH_EXPIRES_IN=365d
# ─ Brute-force / Lock settings ─
LOGIN_MAX_ATTEMPTS=7
LOGIN_LOCK_MINUTES=60

# ── Email (Optional, for notifications later) ─────────
SMTP_HOST=mail.darmist.com
SMTP_PORT=465
SMTP_SECURE=true
SMTP_USER=nestjs_tutorial@darmist.com
SMTP_PASS="YourSecreetPassword@2025"
EMAIL_FROM="DARMIST Lab" <nestjs_tutorial@darmist.com>
```

## ⚙️ 3. Load Config in Each Service

Every service should load env variables globally. Example with Tenant Service:

**File:** `apps/tenant-service/src/tenant-service.module.ts`
```typescript
import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { TenantServiceController } from './tenant-service.controller';
import { TenantServiceService } from './tenant-service.service';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true, // Makes env available everywhere
    }),
  ],
  controllers: [TenantServiceController],
  providers: [TenantServiceService],
})
export class TenantServiceModule {}
```

> 👉 Repeat this for `api-gateway.module.ts`, `auth-service.module.ts`, etc.

## ⚙️ 4. Bootstrap (main.ts)

We’ll make each service self-aware of its name and load HTTP + TCP ports dynamically from `.env`.

**File:** `apps/tenant-service/src/main.ts`
```typescript
import { NestFactory } from '@nestjs/core';
import { MicroserviceOptions, Transport } from '@nestjs/microservices';
import { Logger } from '@nestjs/common';
import * as path from 'node:path';
import { TenantServiceModule } from './tenant-service.module';

// Dynamically infer service name from directory name
const serviceName = path.basename(path.dirname(__filename)) || 'tenant-service';

async function bootstrap() {
  const ENV_PREFIX = serviceName.toUpperCase().replace(/-/g, '_');
  const httpPort = Number(process.env[`${ENV_PREFIX}_HTTP_PORT`]) || 3000;
  const tcpPort = Number(process.env[`${ENV_PREFIX}_TCP_PORT`]) || 4000;

  console.log(`${ENV_PREFIX}_HTTP_PORT`);

  // Create HTTP app
  const app = await NestFactory.create(TenantServiceModule);

  // Attach TCP microservice
  app.connectMicroservice<MicroserviceOptions>({
    transport: Transport.TCP,
    options: { host: '0.0.0.0', port: tcpPort },
  });

  await app.startAllMicroservices();
  await app.listen(httpPort);

  const logger = new Logger(serviceName);
  logger.log(
    `
🚀  ${serviceName} ready!
` +
      `    REST: http://localhost:${httpPort}
` +
      `    TCP : tcp://localhost:${tcpPort}
` +
      `    ENV : ${process.env.NODE_ENV}`,
  );
}
bootstrap();
```

> 👉 Do the same for `auth-service`, `user-service`, `product-service`.
> 👉 For API Gateway, only use `HTTP_PORT` (no TCP needed).

## ⚙️ 5. Quick Environment Check

Let’s confirm the env file is loaded. Add a log in any service (example: `api-gateway.service.ts`):

```typescript
import { Injectable, Logger } from '@nestjs/common';

@Injectable()
export class ApiGatewayService {
  private readonly logger = new Logger(ApiGatewayService.name);

  constructor() {
    this.logger.log(`Loaded env: ${process.env.NODE_ENV}`);
  }

  getHello(): any {
    return { message: '🚀 Welcome to Api Gateway!' };
  }
}
```

## ⚙️ 6. Run & Verify

Start the API Gateway:
```bash
npm run start:dev api-gateway
```

Expected console output:
```
[Nest] 14900   LOG [ApiGatewayService] Loaded env: development
[Nest] 14900   LOG [ApiGateway] 🚀 Api-Gateway ready! REST: http://localhost:3501
```

Start the tenant service:
```bash
npm run start:dev tenant-service
```

Expected console output:
```
[Nest] 14890   LOG [TenantService] 
🚀  tenant-service ready!
    REST: http://localhost:3503
    TCP : tcp://localhost:4503
    ENV : development
```

### Final Verification Checklist for Step 2

- [x] `.env` file created with full set of variables (ports, DB, Redis, JWT, email).
- [x] Each service uses `ConfigModule.forRoot({ isGlobal: true })`.
- [x] `main.ts` loads HTTP + TCP ports dynamically from `.env`.
- [x] Logger prints REST/TCP endpoints + environment on startup.
- [x] Verified console logs show correct ports + env.

With this, your environment is clean, scalable, and production-ready.
