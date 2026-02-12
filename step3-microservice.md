# ✅ Step 3: Microservices Communication (HTTP + TCP) — Auth Service Example

## Goal

*   Auth Service runs both HTTP + TCP.
*   API Gateway connects as a TCP client.
*   A test route (/) on the gateway calls Auth Service over TCP and returns the result.

## ⚙️ 1) Auth Service — TCP handler + health route

**File:** `apps/auth-service/src/auth-service.controller.ts`
```typescript
import { Controller, Get } from '@nestjs/common';
import { MessagePattern, Payload } from '@nestjs/microservices';

@Controller()
export class AuthServiceController {
  @Get('health')
  health() {
    return { ok: true, service: 'auth-service', mode: 'HTTP' };
  }

  @MessagePattern({ cmd: 'get_auth' })
  getAuth(@Payload() data: any) {
    return {
      message: '🔑 Auth Service TCP response',
      receivedData: data ?? null,
      ts: new Date().toISOString(),
    };
  }
}
```

**File:** `apps/auth-service/src/auth-service.module.ts`
```typescript
import { Module } from '@nestjs/common';
import { AuthServiceController } from './auth-service.controller';
import { AuthServiceService } from './auth-service.service';
import { ConfigModule } from '@nestjs/config';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true, // Makes env available everywhere
    }),
  ],
  controllers: [AuthServiceController],
  providers: [AuthServiceService],
})
export class AuthServiceModule {}
```

**File:** `apps/auth-service/src/main.ts`
```typescript
import { NestFactory } from '@nestjs/core';
import { MicroserviceOptions, Transport } from '@nestjs/microservices';
import { Logger } from '@nestjs/common';
import * as path from 'node:path';
import { AuthServiceModule } from '../../auth-service/src/auth-service.module';

// Dynamically infer service name from directory name
const serviceName = path.basename(path.dirname(__filename)) || 'service';

async function bootstrap() {
  const ENV_PREFIX = serviceName.toUpperCase().replace(/-/g, '_');
  const httpPort = Number(process.env[`${ENV_PREFIX}_HTTP_PORT`]) || 3000;
  const tcpPort = Number(process.env[`${ENV_PREFIX}_TCP_PORT`]) || 4000;

  console.log(`${ENV_PREFIX}_HTTP_PORT`);

  // Create HTTP app
  const app = await NestFactory.create(AuthServiceModule);

  // Attach TCP microservice
  app.connectMicroservice<MicroserviceOptions>({
    transport: Transport.TCP,
    options: { host: '0.0.0.0', port: tcpPort },
  });

  await app.startAllMicroservices();
  await app.listen(httpPort);

  const logger = new Logger(serviceName);
  logger.log(
    `\n🚀  ${serviceName} ready!\n` +
      `    REST: http://localhost:${httpPort}\n` +
      `    TCP : tcp://localhost:${tcpPort}\n` +
      `    ENV : ${process.env.NODE_ENV}`,
  );
}
bootstrap();
```

## ⚙️ 2) API Gateway — register TCP client for Auth Service

**File:** `apps/api-gateway/src/api-gateway.module.ts`
```typescript
import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { ClientsModule, Transport } from '@nestjs/microservices';
import { ApiGatewayController } from './api-gateway.controller';
import { ApiGatewayService } from './api-gateway.service';

@Module({
  imports: [
    ConfigModule.forRoot({ isGlobal: true }),
    ClientsModule.registerAsync([
      {
        name: 'AUTH_SERVICE',
        imports: [ConfigModule],
        inject: [ConfigService],
        useFactory: (cfg: ConfigService) => ({
          transport: Transport.TCP,
          options: {
            host: '127.0.0.1',
            port: Number(cfg.get('AUTH_SERVICE_TCP_PORT') || 4502),
          },
        }),
      },
    ]),
  ],
  controllers: [ApiGatewayController],
  providers: [ApiGatewayService],
})
export class ApiGatewayModule {}
```

## ⚙️ 3) API Gateway Controller → Call Auth Service

**File:** `apps/api-gateway/src/api-gateway.controller.ts`
```typescript
import { Controller, Get, Inject } from '@nestjs/common';
import { ClientProxy } from '@nestjs/microservices';
import { lastValueFrom, timeout, catchError, throwError } from 'rxjs';

@Controller()
export class ApiGatewayController {
  constructor(
    @Inject('AUTH_SERVICE') private readonly authClient: ClientProxy,
  ) {}

  @Get('/')
  async root() {
    const obs$ = this.authClient
      .send({ cmd: 'get_auth' }, { via: 'gateway', at: new Date().toISOString() })
      .pipe(
        timeout(2000),
        catchError((err) =>
          throwError(() => new Error(`Auth service error: ${err?.message || err}`)),
        ),
      );

    const response = await lastValueFrom(obs$);
    return response;
  }

  @Get('/health')
  health() {
    return { ok: true, service: 'api-gateway', mode: 'HTTP' };
  }
}
```

## ⚙️ 4) Run in Correct Order

Start Auth Service
```bash
npm run start:dev auth-service
```

Expected log:
```
🚀  auth-service ready!
    REST: http://localhost:3502
    TCP : tcp://127.0.0.1:4502
    ENV : development
```

Start API Gateway
```bash
npm run start:dev api-gateway
```

Expected log:
```
🚀  api-gateway ready!
    REST: http://localhost:3501
```

## ⚙️ 5) Verify Communication

Open in browser:
`http://localhost:3501/`

Expected JSON response:
```json
{
  "message": "🔑 Auth Service TCP response",
  "receivedData": { "via": "gateway", "at": "2025-09-11T..." },
  "ts": "2025-09-11T..."
}
```

Health checks:
`http://localhost:3501/health` → Gateway health
`http://localhost:3502/health` → Auth Service health

### Final Verification Checklist for Step 3 (Auth Service)

- [x] Auth Service runs HTTP 3502 + TCP 4502
- [x] API Gateway registers TCP client for Auth Service
- [x] GET / on Gateway returns TCP response from Auth Service

> 🎉 **Important Suggestion**  
> <span style="color:red">Repeat the process with at least another service to clear your concept. Please follow this guideline before jumping to the next step.</span>

