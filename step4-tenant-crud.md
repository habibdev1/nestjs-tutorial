# ✅ Step 4: MongoDB (Mongoose) + Tenant CRUD (UUID + Common API Response)

## ⚙️ 1) Update Environment Variables

Make sure `.env` has:
```dotenv
TENANT_SERVICE_HTTP_PORT=3503
TENANT_SERVICE_TCP_PORT=4503
MONGO_URI_TENANT=mongodb://localhost:27017/nestjs_tutorial_tenant_db
```

## ⚙️ 2) Install Required Dependencies

```bash
npm i @nestjs/mongoose mongoose @nestjs/config class-validator class-transformer uuid
npm i -D @types/uuid
npm install @nestjs/mapped-types
```

## ⚙️ 3) Add Common Response Utility (shared lib)

We’ll use a shared lib so all services return the same format API response.
```bash
nest g library common-lib
```

**File:** `libs/common-lib/src/response.util.ts`
```typescript
export function apiResponse(
  message: string,
  data: any = null,
  meta: any = null,
) {
  return {
    message,
    data,
    ...(meta ? { meta } : {}),
    ts: new Date().toISOString(),
  };
}
```

**File:** `libs/common-lib/src/index.ts`
```typescript
export * from './common-lib.module';
export * from './common-lib.service';

export * from './response.util';
```

✅ Now, every service can import:
```typescript
import { apiResponse } from '@app/common-lib';
```
Note: After creating a new library, you will need to rerun the project. Otherwise, the lib won’t be found.

## ⚙️ 4) Tenant Schema (UUID + Statuses)

Create `apps/tenant-service/src/schemas/tenant.schema.ts`
```typescript
import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';
import { v4 as uuidv4 } from 'uuid';

export type TenantDocument = Tenant & Document;

export enum TenantStatus {
  PENDING = 'PENDING',
  ACTIVE = 'ACTIVE',
  INACTIVE = 'INACTIVE',
  LOCKED = 'LOCKED',
  SUSPENDED = 'SUSPENDED',
}

@Schema({ timestamps: true, versionKey: false })
export class Tenant {
  @Prop({
    type: String,
    default: uuidv4,
  })
  _id: string; // UUID primary key

  @Prop({ required: true, unique: true, trim: true, lowercase: true })
  name: string;

  @Prop({ required: true, trim: true })
  displayName: string;

  @Prop({ required: true, trim: true })
  contactEmail: string;

  @Prop({ type: String, enum: TenantStatus, default: TenantStatus.PENDING })
  status: TenantStatus;

  @Prop({ type: Boolean, default: false })
  deleted: boolean;
}

export const TenantSchema = SchemaFactory.createForClass(Tenant);

TenantSchema.index({ name: 1 }, { unique: true });
TenantSchema.index({ status: 1, deleted: 1 });
```

## ⚙️ 5) DTOs (Validation)

Create `apps/tenant-service/src/dto/`

**File:** `create-tenant.dto.ts`
```typescript
import { IsEmail, IsEnum, IsOptional, IsString, Matches, MinLength } from 'class-validator';
import { TenantStatus } from '../schemas/tenant.schema';

export class CreateTenantDto {
  @IsString()
  @MinLength(3)
  @Matches(/^[a-z0-9-]+$/)
  name: string;

  @IsString()
  @MinLength(3)
  displayName: string;

  @IsEmail()
  contactEmail: string;

  @IsOptional()
  @IsEnum(TenantStatus)
  status?: TenantStatus;
}
```

**File:** `update-tenant.dto.ts`
```typescript
import { PartialType } from '@nestjs/mapped-types';
import { CreateTenantDto } from './create-tenant.dto';

export class UpdateTenantDto extends PartialType(CreateTenantDto) {}
```

**File:** `change-status.dto.ts`
```typescript
import { IsEnum } from 'class-validator';
import { TenantStatus } from '../schemas/tenant.schema';

export class ChangeStatusDto {
  @IsEnum(TenantStatus)
  status: TenantStatus;
}
```

## ⚙️ 6) Update Module to Wire DB + Schema

**Your file:** `apps/tenant-service/src/tenant-service.module.ts`
```typescript
import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { MongooseModule } from '@nestjs/mongoose';
import { TenantServiceController } from './tenant-service.controller';
import { TenantServiceService } from './tenant-service.service';
import { Tenant, TenantSchema } from './schemas/tenant.schema';

@Module({
  imports: [
    ConfigModule.forRoot({ isGlobal: true }),

    // DB connection
    MongooseModule.forRootAsync({
      useFactory: (cfg: ConfigService) => ({
        uri: cfg.get<string>('MONGO_URI_TENANT'),
      }),
      inject: [ConfigService],
    }),

    // Register Tenant schema
    MongooseModule.forFeature([{ name: Tenant.name, schema: TenantSchema }]),
  ],
  controllers: [TenantServiceController],
  providers: [TenantServiceService],
})
export class TenantServiceModule {}
```

## ⚙️ 7) Service Implementation

**Your file:** `apps/tenant-service/src/tenant-service.service.ts`
```typescript
import { Injectable, NotFoundException, ConflictException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model, FilterQuery } from 'mongoose';
import { Tenant, TenantDocument, TenantStatus } from './schemas/tenant.schema';
import { CreateTenantDto } from './dto/create-tenant.dto';
import { UpdateTenantDto } from './dto/update-tenant.dto';

@Injectable()
export class TenantServiceService {
  constructor(
    @InjectModel(Tenant.name) private readonly tenantModel: Model<TenantDocument>,
  ) {}

  async create(dto: CreateTenantDto): Promise<Tenant> {
    try {
      const tenant = new this.tenantModel(dto);
      return await tenant.save();
    } catch (e: any) {
      if (e?.code === 11000) throw new ConflictException('Tenant name already exists');
      throw e;
    }
  }

  async findAll(status?: TenantStatus): Promise<Tenant[]> {
    const query: FilterQuery<Tenant> = { deleted: false };
    if (status) query.status = status;
    return this.tenantModel.find(query).sort({ createdAt: -1 }).lean().exec();
  }

  async findById(id: string): Promise<Tenant> {
    const doc = await this.tenantModel.findOne({ _id: id, deleted: false }).lean().exec();
    if (!doc) throw new NotFoundException('Tenant not found');
    return doc;
  }

  async update(id: string, dto: UpdateTenantDto): Promise<Tenant> {
    const updated = await this.tenantModel
      .findOneAndUpdate({ _id: id, deleted: false }, { $set: dto }, { new: true, runValidators: true })
      .lean().exec();
    if (!updated) throw new NotFoundException('Tenant not found');
    return updated;
  }

  async changeStatus(id: string, status: TenantStatus): Promise<Tenant> {
    const updated = await this.tenantModel
      .findOneAndUpdate({ _id: id, deleted: false }, { $set: { status } }, { new: true })
      .lean().exec();
    if (!updated) throw new NotFoundException('Tenant not found');
    return updated;
  }

  async softDelete(id: string): Promise<{ deleted: boolean }> {
    const res = await this.tenantModel
      .findOneAndUpdate(
        { _id: id, deleted: false },
        { $set: { deleted: true, status: TenantStatus.INACTIVE } },
      )
      .lean().exec();
    if (!res) throw new NotFoundException('Tenant not found');
    return { deleted: true };
  }
}
```

## ⚙️ 8) Controller with Response Wrapper

**Your file:** `apps/tenant-service/src/tenant-service.controller.ts`
```typescript
import { Body, Controller, Delete, Get, Param, Patch, Post, Query } from '@nestjs/common';
import { TenantServiceService } from './tenant-service.service';
import { CreateTenantDto } from './dto/create-tenant.dto';
import { UpdateTenantDto } from './dto/update-tenant.dto';
import { ChangeStatusDto } from './dto/change-status.dto';
import { TenantStatus } from './schemas/tenant.schema';
import { apiResponse } from '@app/common-lib';

@Controller('tenants')
export class TenantServiceController {
  constructor(private readonly service: TenantServiceService) {}

  @Post()
  async create(@Body() dto: CreateTenantDto) {
    const data = await this.service.create(dto);
    return apiResponse('Tenant created successfully', data);
  }

  @Get()
  async findAll(@Query('status') status?: TenantStatus) {
    const data = await this.service.findAll(status as TenantStatus);
    return apiResponse('Tenant list fetched successfully', data);
  }

  @Get(':id')
  async findOne(@Param('id') id: string) {
    const data = await this.service.findById(id);
    return apiResponse('Tenant details fetched successfully', data);
  }

  @Patch(':id')
  async update(@Param('id') id: string, @Body() dto: UpdateTenantDto) {
    const data = await this.service.update(id, dto);
    return apiResponse('Tenant updated successfully', data);
  }

  @Patch(':id/status')
  async changeStatus(@Param('id') id: string, @Body() body: ChangeStatusDto) {
    const data = await this.service.changeStatus(id, body.status);
    return apiResponse(`Tenant status changed to ${body.status}`, data);
  }

  @Delete(':id')
  async softDelete(@Param('id') id: string) {
    const data = await this.service.softDelete(id);
    return apiResponse('Tenant deleted successfully', data);
  }
}
```

## ⚙️ 9) Bootstrap (main.ts)

**File:** `apps/tenant-service/src/main.ts`
```typescript
import { NestFactory } from '@nestjs/core';
import { MicroserviceOptions, Transport } from '@nestjs/microservices';
import { Logger, ValidationPipe } from '@nestjs/common';
import { TenantServiceModule } from './tenant-service.module';

async function bootstrap() {
  const serviceName = 'tenant-service';
  const ENV_PREFIX = serviceName.toUpperCase().replace(/-/g, '_');
  const httpPort = Number(process.env[`${ENV_PREFIX}_HTTP_PORT`]) || 3503;
  const tcpPort = Number(process.env[`${ENV_PREFIX}_TCP_PORT`]) || 4503;

  const app = await NestFactory.create(TenantServiceModule);

  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
    }),
  );

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
      `    TCP : tcp://localhost:${tcpPort}\n`,
  );
}
bootstrap();
```

## ⚙️ 10) Example Request & Response

```bash
curl -s POST http://localhost:3503/tenants \
  -H 'Content-Type: application/json' \
  -d '{"name":"darmist1","displayName":"DARMIST Lab Sweden","contactEmail":"ops@darmist.com"}'
```

Response
```json
{
  "message": "Tenant created successfully",
  "data": {
    "_id": "7c3e0afc-7a8a-4e52-8c38-0d4f74f3c42b",
    "name": "darmist1",
    "displayName": "DARMIST Lab Sweden",
    "contactEmail": "ops@darmist.com",
    "status": "PENDING",
    "deleted": false,
    "createdAt": "2025-09-11T12:10:00.512Z",
    "updatedAt": "2025-09-11T12:10:00.512Z"
  },
  "ts": "2025-09-11T12:10:00.512Z"
}
```

Open `http://localhost:3503/tenants` in browser to load all tenant data.

## ⚙️ 11) Add Tenant Microservice Endpoints (TCP handlers)

Inside `apps/tenant-service/src/tenant-service.controller.ts`, extend the controller with `@MessagePattern` handlers.

```typescript
import {
  Body,
  Controller,
  Delete,
  Get,
  Param,
  Patch,
  Post,
  Query,
} from '@nestjs/common';
import { MessagePattern, Payload } from '@nestjs/microservices';
import { TenantServiceService } from './tenant-service.service';
import { CreateTenantDto } from './dto/create-tenant.dto';
import { UpdateTenantDto } from './dto/update-tenant.dto';
import { ChangeStatusDto } from './dto/change-status.dto';
import { TenantStatus } from './schemas/tenant.schema';
import { apiResponse } from '@app/common-lib';

@Controller('tenants')
export class TenantServiceController {
  constructor(private readonly service: TenantServiceService) {}

  // ---------- REST Endpoints ----------
  @Post()
  async create(@Body() dto: CreateTenantDto) {
    const data = await this.service.create(dto);
    return apiResponse('Tenant created successfully', data);
  }

  @Get()
  async findAll(@Query('status') status?: TenantStatus) {
    const data = await this.service.findAll(status as TenantStatus);
    return apiResponse('Tenant list fetched successfully', data);
  }

  @Get(':id')
  async findOne(@Param('id') id: string) {
    const data = await this.service.findById(id);
    return apiResponse('Tenant details fetched successfully', data);
  }

  @Patch(':id')
  async update(@Param('id') id: string, @Body() dto: UpdateTenantDto) {
    const data = await this.service.update(id, dto);
    return apiResponse('Tenant updated successfully', data);
  }

  @Patch(':id/status')
  async changeStatus(@Param('id') id: string, @Body() body: ChangeStatusDto) {
    const data = await this.service.changeStatus(id, body.status);
    return apiResponse(`Tenant status changed to ${body.status}`, data);
  }

  @Delete(':id')
  async softDelete(@Param('id') id: string) {
    const data = await this.service.softDelete(id);
    return apiResponse('Tenant deleted successfully', data);
  }

  // ---------- Convenience REST APIs ----------
  @Patch('by-name/:name/status')
  async changeStatusByName(
    @Param('name') name: string,
    @Body() body: ChangeStatusDto,
  ) {
    const tenant = await this.service.findByName(name); // Assuming findByName exists
    const data = await this.service.changeStatus(tenant._id, body.status);
    return apiResponse(`Tenant status changed to ${body.status}`, data);
  }

  @Get('by-name/:name/status')
  async getStatusByName(@Param('name') name: string) {
    const tenant = await this.service.findByName(name); // Assuming findByName exists
    return apiResponse('Tenant status fetched successfully', {
      name: tenant.name,
      status: tenant.status,
    });
  }

  // ---------- Microservice Endpoints (TCP) ----------
  @MessagePattern({ cmd: 'tenant.create' })
  async handleCreate(@Payload() dto: CreateTenantDto) {
    const data = await this.service.create(dto);
    return apiResponse('Tenant created successfully (TCP)', data);
  }

  @MessagePattern({ cmd: 'tenant.findAll' })
  async handleFindAll(@Payload() status?: TenantStatus) {
    const data = await this.service.findAll(status as TenantStatus);
    return apiResponse('Tenant list fetched successfully (TCP)', data);
  }

  @MessagePattern({ cmd: 'tenant.findById' })
  async handleFindById(@Payload() id: string) {
    const data = await this.service.findById(id);
    return apiResponse('Tenant fetched successfully (TCP)', data);
  }

  @MessagePattern({ cmd: 'tenant.findByName' })
  async handleFindByName(@Payload() name: string) {
    const data = await this.service.findByName(name);
    return apiResponse('Tenant fetched successfully (TCP)', data);
  }

  @MessagePattern({ cmd: 'tenant.update' })
  async handleUpdate(@Payload() payload: { id: string; dto: UpdateTenantDto }) {
    const data = await this.service.update(payload.id, payload.dto);
    return apiResponse('Tenant updated successfully (TCP)', data);
  }

  @MessagePattern({ cmd: 'tenant.changeStatus' })
  async handleChangeStatus(
    @Payload() payload: { id: string; status: TenantStatus },
  ) {
    const data = await this.service.changeStatus(payload.id, payload.status);
    return apiResponse(`Tenant status changed to ${payload.status} (TCP)`, data);
  }

  @MessagePattern({ cmd: 'tenant.changeStatusByName' })
  async handleChangeStatusByName(
    @Payload() payload: { name: string; status: TenantStatus },
  ) {
    const tenant = await this.service.findByName(payload.name);
    const data = await this.service.changeStatus(tenant._id, payload.status);
    return apiResponse(
      `Tenant status changed to ${payload.status} (TCP)`,
      data,
    );
  }

  @MessagePattern({ cmd: 'tenant.getStatusByName' })
  async handleGetStatusByName(@Payload() name: string) {
    const tenant = await this.service.findByName(name);
    return apiResponse('Tenant status fetched successfully (TCP)', {
      name: tenant.name,
      status: tenant.status,
    });
  }

  @MessagePattern({ cmd: 'tenant.softDelete' })
  async handleSoftDelete(@Payload() id: string) {
    const data = await this.service.softDelete(id);
    return apiResponse('Tenant deleted successfully (TCP)', data);
  }

  @MessagePattern({ cmd: 'tenant.validate' })
  async handleValidate(@Payload() name: string) {
    try {
      const tenant = await this.service.findByName(name);
      return apiResponse('Tenant validated successfully (TCP)', {
        valid: true,
        tenant,
      });
    } catch {
      return apiResponse('Tenant validation failed (TCP)', { valid: false });
    }
  }
}
```

## ⚙️ 12) Add findByName Method in Service

Extend `apps/tenant-service/src/tenant-service.service.ts` with a `findByName` method to get tenants by name:
```typescript
async findByName(name: string): Promise<Tenant> {
  const doc = await this.tenantModel.findOne({ name, deleted: false }).lean().exec();
  if (!doc) throw new NotFoundException('Tenant not found');
  return doc;
}
```

## ⚙️ 13) Add Tenant Gateway Controller

**File:** `apps/api-gateway/src/tenant-gateway.controller.ts`
```typescript
import {
  Body,
  Controller,
  Delete,
  Get,
  Inject,
  Param,
  Patch,
  Post,
  Query,
} from '@nestjs/common';
import { ClientProxy } from '@nestjs/microservices';
import { lastValueFrom } from 'rxjs';
import { apiResponse } from '@app/common-lib';
import { CreateTenantDto } from '../../tenant-service/src/dto/create-tenant.dto';
import { TenantStatus } from '../../tenant-service/src/schemas/tenant.schema';
import { UpdateTenantDto } from '../../tenant-service/src/dto/update-tenant.dto';
import { ChangeStatusDto } from '../../tenant-service/src/dto/change-status.dto';

@Controller('gateway/tenants')
export class TenantGatewayController {
  constructor(
    @Inject('TENANT_SERVICE') private readonly tenantClient: ClientProxy,
  ) {}

  @Post()
  async create(@Body() dto: CreateTenantDto) {
    const result = await lastValueFrom(
      this.tenantClient.send({ cmd: 'tenant.create' }, dto),
    );
    return apiResponse('Tenant created via Gateway', result.data);
  }

  @Get()
  async findAll(@Query('status') status?: TenantStatus) {
    const result = await lastValueFrom(
      this.tenantClient.send({ cmd: 'tenant.findAll' }, status ?? ''),
    );
    return apiResponse('Tenant list via Gateway', result.data);
  }

  @Get(':id')
  async findById(@Param('id') id: string) {
    const result = await lastValueFrom(
      this.tenantClient.send({ cmd: 'tenant.findById' }, id),
    );
    return apiResponse('Tenant fetched via Gateway', result.data);
  }

  @Get('by-name/:name')
  async findByName(@Param('name') name: string) {
    const result = await lastValueFrom(
      this.tenantClient.send({ cmd: 'tenant.findByName' }, name),
    );
    return apiResponse('Tenant fetched via Gateway', result.data);
  }

  @Patch(':id')
  async update(@Param('id') id: string, @Body() dto: UpdateTenantDto) {
    const result = await lastValueFrom(
      this.tenantClient.send({ cmd: 'tenant.update' }, { id, dto }),
    );
    return apiResponse('Tenant updated via Gateway', result.data);
  }

  @Patch(':id/status')
  async changeStatus(@Param('id') id: string, @Body() body: ChangeStatusDto) {
    const result = await lastValueFrom(
      this.tenantClient.send(
        { cmd: 'tenant.changeStatus' },
        { id, status: body.status },
      ),
    );
    return apiResponse(
      `Tenant status changed to ${body.status} via Gateway`,
      result.data,
    );
  }

  @Patch('by-name/:name/status')
  async changeStatusByName(
    @Param('name') name: string,
    @Body() body: ChangeStatusDto,
  ) {
    const result = await lastValueFrom(
      this.tenantClient.send(
        { cmd: 'tenant.changeStatusByName' },
        { name, status: body.status },
      ),
    );
    return apiResponse(
      `Tenant status changed to ${body.status} via Gateway`,
      result.data,
    );
  }

  @Get('by-name/:name/status')
  async getStatusByName(@Param('name') name: string) {
    const result = await lastValueFrom(
      this.tenantClient.send({ cmd: 'tenant.getStatusByName' }, name),
    );
    return apiResponse('Tenant status via Gateway', result.data);
  }

  @Delete(':id')
  async softDelete(@Param('id') id: string) {
    const result = await lastValueFrom(
      this.tenantClient.send({ cmd: 'tenant.softDelete' }, id),
    );
    return apiResponse('Tenant deleted via Gateway', result.data);
  }

  @Get('validate/:name')
  async validateTenant(@Param('name') name: string) {
    const result = await lastValueFrom(
      this.tenantClient.send({ cmd: 'tenant.validate' }, name),
    );
    return apiResponse('Tenant validation via Gateway', result.data);
  }
}
```

## ⚙️ 14) Configure API Gateway to Call Tenant Service

We connect API Gateway to Tenant Service over TCP.
Remember to add `TenantGatewayController` in the controllers list. Otherwise, api gateway endpoints won’t be available.

**File:** `apps/api-gateway/src/api-gateway.module.ts`
```typescript
import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { ClientsModule, Transport } from '@nestjs/microservices';
import { ApiGatewayController } from './api-gateway.controller';
import { ApiGatewayService } from './api-gateway.service';
import { TenantGatewayController } from './tenant-gateway.controller';

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
      // (You’ll add PRODUCT_SERVICE similarly later)
    ]),
  ],
  controllers: [ApiGatewayController, TenantGatewayController],
  providers: [ApiGatewayService],
})
export class ApiGatewayModule {}
```


## ⚙️ 15) Verify the Flow

Run both services:
```bash
npx nest start tenant-service --watch
npx nest start api-gateway --watch
```
Test REST directly on Tenant Service
```bash
curl -s http://localhost:3503/tenants/by-name/darmist1/status | jq
```
Test through API Gateway
```bash
curl -s http://localhost:3501/gateway/tenants/by-name/darmist1/status | jq
```
Expected Response
```json
{
  "message": "Tenant status fetched via Gateway",
  "data": {
    "name": "darmist1",
    "status": "ACTIVE"
  },
  "ts": "2025-09-11T14:20:15.512Z"
}
```


## ⚙️ 16) Test with cURL Commands

Create a tenant
```bash
curl -X POST http://localhost:3501/gateway/tenants \
  -H "Content-Type: application/json" \
  -d '{
    "name": "skyflow1",
    "displayName": "SkyFlow Technologies",
    "contactEmail": "contact@skyflow.com"
  }'
```

Get all tenants
```bash
curl -X GET "http://localhost:3501/gateway/tenants"
```
With status filter:
```bash
curl -X GET "http://localhost:3501/gateway/tenants?status=ACTIVE"
```

Get tenant by ID
```bash
curl -X GET http://localhost:3501/gateway/tenants/2f4a1c8d-9b67-4db0-92a7-1a9c2e8d45ef
```

Get tenant by name
```bash
curl -X GET http://localhost:3501/gateway/tenants/by-name/skyflow1
```

Update a tenant
```bash
curl -X PATCH http://localhost:3501/gateway/tenants/2f4a1c8d-9b67-4db0-92a7-1a9c2e8d45ef \
  -H "Content-Type: application/json" \
  -d '{
    "displayName": "SkyFlow Global",
    "contactEmail": "support@skyflow.com"
  }'
```

Change tenant status by ID
```bash
curl -X PATCH http://localhost:3501/gateway/tenants/2f4a1c8d-9b67-4db0-92a7-1a9c2e8d45ef/status \
  -H "Content-Type: application/json" \
  -d '{
    "status": "SUSPENDED"
  }'
```

Change tenant status by name
```bash
curl -X PATCH http://localhost:3501/gateway/tenants/by-name/skyflow1/status \
  -H "Content-Type: application/json" \
  -d '{
    "status": "ACTIVE"
  }'
```

Get tenant status by name
```bash
curl -X GET http://localhost:3501/gateway/tenants/by-name/skyflow1/status
```

Soft delete tenant
```bash
curl -X DELETE http://localhost:3501/gateway/tenants/2f4a1c8d-9b67-4db0-92a7-1a9c2e8d45ef
```

Validate tenant by name
```bash
curl -X GET http://localhost:3501/gateway/tenants/validate/skyflow1
```


## ⚙️ 17) Pagination Support

Now, we will implement paginated data loading for tenant records. 
✅ `tenant-service.controller.ts`
```typescript
@Get()
async findAll(
  @Query('status') status?: TenantStatus,
  @Query('page') page?: number,
  @Query('pageSize') pageSize?: number,
) {
  const { data, total, meta } = await this.service.findAll(
    status as TenantStatus,
    page,
    pageSize,
  );
  return apiResponse('Tenant list fetched successfully', data, meta);
}

// ---------- TCP ----------
@MessagePattern({ cmd: 'tenant.findAll' })
async handleFindAll(
  @Payload() payload: { status?: TenantStatus; page?: number; pageSize?: number },
) {
  const { data, total, meta } = await this.service.findAll(
    payload.status as TenantStatus,
    payload.page,
    payload.pageSize,
  );
  return apiResponse('Tenant list fetched successfully (TCP)', data, meta);
}
```

✅ `tenant-service.service.ts`
```typescript
async findAll(
  status?: TenantStatus,
  page = 1,
  pageSize = 10,
): Promise<{ data: Tenant[]; total: number; meta: any }> {
  const query: FilterQuery<Tenant> = { deleted: false };
  if (status) query.status = status;

  const total = await this.tenantModel.countDocuments(query);

  // Negative page means "all data"
  if (page < 0) {
    const data = await this.tenantModel.find(query).sort({ createdAt: -1 }).lean().exec();
    return {
      data,
      total,
      meta: {
        total,
        page: -1,
        pageSize: total,
        totalPages: 1,
      },
    };
  }

  const skip = (page - 1) * pageSize;
  const data = await this.tenantModel
    .find(query)
    .sort({ createdAt: -1 })
    .skip(skip)
    .limit(pageSize)
    .lean()
    .exec();

  return {
    data,
    total,
    meta: {
      total,
      page,
      pageSize,
      totalPages: Math.ceil(total / pageSize) || 1,
    },
  };
}
```


✅ `tenant-gateway.controller.ts`
```typescript
@Get()
async findAll(
  @Query('status') status?: TenantStatus,
  @Query('page') page?: number,
  @Query('pageSize') pageSize?: number,
) {
  const result = await lastValueFrom(
    this.tenantClient.send(
      { cmd: 'tenant.findAll' },
      {
        status: status ?? null,
        page: page !== undefined ? Number(page) : 1,
        pageSize: pageSize !== undefined ? Number(pageSize) : 10,
      },
    ),
  );
  return apiResponse('Tenant list via Gateway', result.data, result.meta);
}
```

✅ Example Calls
Default (page=1, pageSize=10):
```bash
curl -s "http://localhost:3501/gateway/tenants" |jq
```

Specific page:
```bash
curl -s "http://localhost:3501/gateway/tenants?page=2&pageSize=5"
```

All data (page < 0):
```bash
curl -s "http://localhost:3501/gateway/tenants?page=-1"
```
