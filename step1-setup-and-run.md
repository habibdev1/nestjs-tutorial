# ✅ Step 1: Setting Up nestjs-tutorial Monorepo

## ⚙️ 1. Install Nest CLI & Create Monorepo

First, install Nest CLI globally if you don’t already have it:

```sh
npm install -g @nestjs/cli
```

Verify version:

```sh
nest --version
```

Expected output (or higher):

```
11.0.10
```

Now create the project:

```sh
nest new nestjs-tutorial --package-manager npm
cd nestjs-tutorial
```

Choose `npm` when asked.
This creates a clean NestJS workspace.

## ⚙️ 2. Generate Microservices (apps)

We’ll generate 5 apps inside `/apps`:

```sh
nest generate app api-gateway
nest generate app auth-service
nest generate app tenant-service
nest generate app user-service
nest generate app product-service
```

Updated structure:

```
nestjs-tutorial/
├── apps/
│   ├── api-gateway/
│   ├── auth-service/
│   ├── tenant-service/
│   ├── user-service/
│   └── product-service/
```

## ⚙️ 3. Generate Shared Libraries (libs)

Now create reusable libraries:

```sh
nest generate library auth-lib
nest generate library common-lib
nest generate library database-lib
nest generate library email-lib
nest generate library logger-lib
nest generate library redis-lib
```

Updated structure:

```
nestjs-tutorial/
├── libs/
│   ├── auth-lib/
│   ├── common-lib/
│   ├── database-lib/
│   ├── email-lib/
│   ├── logger-lib/
│   └── redis-lib/
```

## ⚙️ 4. Install Dependencies

We’ll need Mongoose, Redis, Winston, and validation libraries:

```sh
npm install @nestjs/mongoose mongoose
npm install @nestjs/microservices
npm install redis ioredis
npm install winston nest-winston
npm install @nestjs/config
npm install class-validator class-transformer
npm install -D @types/redis @types/uuid
```

## ⚙️ 5. Configure Explicit Ports & Logger

Update each service’s `main.ts` to use explicit ports with a logger context.

Example: `apps/api-gateway/src/main.ts`

```typescript
import { NestFactory } from '@nestjs/core';
import { ApiGatewayModule } from './api-gateway.module';
import { Logger } from '@nestjs/common';

async function bootstrap() {
  const app = await NestFactory.create(ApiGatewayModule);
  const logger = new Logger('ApiGateway');
  const port = 3501; // HTTP port
  await app.listen(port);
  logger.log(`🚀 Api-Gateway is running on: http://localhost:${port}`);
}
bootstrap();
```

Example: `apps/auth-service/src/main.ts`

```typescript
import { NestFactory } from '@nestjs/core';
import { Transport, MicroserviceOptions } from '@nestjs/microservices';
import { AuthServiceModule } from './auth-service.module';
import { Logger } from '@nestjs/common';

async function bootstrap() {
  const app = await NestFactory.createMicroservice<MicroserviceOptions>(
    AuthServiceModule,
    {
      transport: Transport.TCP,
      options: {
        host: '127.0.0.1',
        port: 4501, // TCP port
      },
    },
  );

  const logger = new Logger('AuthService');
  await app.listen();
  logger.log('🚀 Auth-Service TCP Microservice running on port 4501');
}
bootstrap();
```

👉 Do the same for `tenant-service` (4502), `user-service` (4503), and `product-service` (4504).

## ⚙️ 6. Custom Welcome Messages

Each service should have a clear welcome response for easy testing.

Example: `apps/api-gateway/src/api-gateway.controller.ts`

```typescript
import { Controller, Get } from '@nestjs/common';

@Controller()
export class AppController {
  @Get()
  getHello(): any {
    return { message: '🚀 Welcome to Api Gateway!' };
  }
}
```

Apply similar in each service:

| Service         | Port | Message                             |
| --------------- | ---- | ----------------------------------- |
| api-gateway     | 3501 | "🚀 Welcome to Api Gateway!"        |
| auth-service    | 4501 | "🔑 Welcome to Auth Service (TCP)!"   |
| tenant-service  | 4502 | "🏢 Welcome to Tenant Service (TCP)!" |
| user-service    | 4503 | "👤 Welcome to User Service (TCP)!"   |
| product-service | 4504 | "📦 Welcome to Product Service (TCP)!" |

## ⚙️ 7. Verify Each Service

Run each service in a separate terminal:

```sh
npm run start:dev api-gateway
npm run start:dev auth-service
npm run start:dev tenant-service
npm run start:dev user-service
npm run start:dev product-service
```

Expected logs:

```
[Nest] 12345   LOG [ApiGateway] 🚀 Api-Gateway is running on: http://localhost:3501
[Nest] 12346   LOG [AuthService] 🚀 Auth-Service TCP Microservice running on port 4501
[Nest] 12347   LOG [TenantService] 🚀 Tenant-Service TCP Microservice running on port 4502
[Nest] 12348   LOG [UserService] 🚀 User-Service TCP Microservice running on port 4503
[Nest] 12349   LOG [ProductService] 🚀 Product-Service TCP Microservice running on port 4504
```

Verification in browser:

`http://localhost:3501` → `{"message":"🚀 Welcome to Api Gateway!"}`

TCP services won’t show in browser (we’ll connect via Gateway later).

---

## ⚙️ 8. Dynamic Runner Script (Optional)

Instead of running each service in separate terminals, you can start all services dynamically with a single script.
We won’t modify `package.json`; we’ll call the Nest CLI directly via `npx`.

### Create Script

File: `tools/run-all.sh`

```sh
#!/usr/bin/env bash
# tools/run-all.sh
# ------------------------------------------------------------
# Starts all NestJS services in watch mode (in parallel)
# ------------------------------------------------------------

set -e  # Exit on first error

# List of Nest projects (as created by `nest g app ...`)
SERVICES=(
  api-gateway
  auth-service
  tenant-service
  product-service
  user-service
)

# Start each service in the background using Nest CLI directly
for SERVICE in "${SERVICES[@]}"; do
  echo "▶︎ Starting $SERVICE..."
  npx nest start "$SERVICE" --watch &
done

# Trap Ctrl+C and stop all background jobs
trap 'echo; echo "🛑 Stopping all services..."; kill 0' SIGINT

# Wait for all background jobs
wait
```

Make it executable:

```sh
chmod +x tools/run-all.sh
```

### Run & Verify

From repo root:

```sh
./tools/run-all.sh
```

Expected trimmed output:

```
▶︎ Starting api-gateway...
▶︎ Starting auth-service...
▶︎ Starting tenant-service...
▶︎ Starting product-service...

[Nest] 18438  - 09/11/2025, 1:05:14 PM     LOG [NestFactory] Starting Nest application...
[Nest] 18439  - 09/11/2025, 1:05:14 PM     LOG [NestFactory] Starting Nest application...
[Nest] 18440  - 09/11/2025, 1:05:14 PM     LOG [NestFactory] Starting Nest application...
[Nest] 18438  - 09/11/2025, 1:05:14 PM     LOG [InstanceLoader] TenantServiceModule dependencies initialized +17ms
[Nest] 18440  - 09/11/2025, 1:05:14 PM     LOG [InstanceLoader] ProductServiceModule dependencies initialized +18ms
[Nest] 18439  - 09/11/2025, 1:05:14 PM     LOG [InstanceLoader] AuthServiceModule dependencies initialized +21ms
[Nest] 18440  - 09/11/2025, 1:05:14 PM     LOG [NestMicroservice] Nest microservice successfully started +17ms
[Nest] 18440  - 09/11/2025, 1:05:14 PM     LOG [AuthService] 🚀 Product-Service TCP Microservice running on port 4504
[Nest] 18438  - 09/11/2025, 1:05:14 PM     LOG [NestMicroservice] Nest microservice successfully started +19ms
[Nest] 18438  - 09/11/2025, 1:05:14 PM     LOG [AuthService] 🚀 Tenant-Service TCP Microservice running on port 4502
[Nest] 18439  - 09/11/2025, 1:05:14 PM     LOG [NestMicroservice] Nest microservice successfully started +18ms
[Nest] 18439  - 09/11/2025, 1:05:14 PM     LOG [AuthService] 🚀 Auth-Service TCP Microservice running on port 4501
[Nest] 18441  - 09/11/2025, 1:05:14 PM     LOG [NestFactory] Starting Nest application...
[Nest] 18441  - 09/11/2025, 1:05:14 PM     LOG [InstanceLoader] ApiGatewayModule dependencies initialized +18ms
[Nest] 18441  - 09/11/2025, 1:05:14 PM     LOG [RoutesResolver] ApiGatewayController {/}: +7ms
[Nest] 18441  - 09/11/2025, 1:05:14 PM     LOG [RouterExplorer] Mapped {/, GET} route +4ms
[Nest] 18441  - 09/11/2025, 1:05:14 PM     LOG [NestApplication] Nest application successfully started +2ms
[Nest] 18441  - 09/11/2025, 1:05:14 PM     LOG [ApiGateway] 🚀 Api-Gateway is running on: http://localhost:3501
```

This way you can spin up all services with one command while keeping `package.json` clean.

---

## Final Verification Checklist for Step 1

- [x] Monorepo created (`nestjs-tutorial`)
- [x] Apps generated (gateway, auth, tenant, user, product)
- [x] Libs generated (common, database, email, redis, logger, auth)
- [x] Dependencies installed (mongoose, redis, winston, microservices, config)
- [x] Ports assigned (HTTP 3501, TCP 4501–4504)
- [x] Logger contexts set for each service
- [x] Custom welcome messages added
- [x] Verified startup logs for all services

👉 Now you have a working monorepo with 5 services + 6 shared libs all running independently.
