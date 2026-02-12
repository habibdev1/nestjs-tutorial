# ✅ Step 10 — Swagger / OpenAPI for NestJS

## Goals
*   Consistent Swagger setup for every app (api-gateway, auth-service, tenant-service, product-service).
*   Reusable helper in common-lib to avoid duplicate boilerplate.
*   Out-of-the-box support for:
    *   JWT Bearer auth (access token).
    *   Tenant header: `x-tenant-id` (global helper decorator).
    *   Public endpoints (no auth).
    *   DTO schemas, enums, pagination and examples.
    *   OpenAPI JSON export to `/openapi/*.json`.

## ⚙️ 1) Install Swagger packages
```bash
npm i @nestjs/swagger swagger-ui-express
```
We’ll keep Swagger UI enabled in non-production by default. You can override per app.

## ⚙️ 2) Common Swagger helper (in common-lib)
Create a small utility to set up Swagger the same way in each service.

`libs/common-lib/src/swagger.ts`
```typescript
import { INestApplication } from '@nestjs/common';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import { writeFileSync, mkdirSync, existsSync } from 'fs';
import { join } from 'path';

/**
 * Shared Swagger setup for all apps.
 *
 * @param app - The Nest application.
 * @param opts - Title/description/version and routePrefix for docs UI.
 */
export function setupSwagger(
  app: INestApplication,
  opts: {
    title: string;
    description: string;
    version?: string;
    routePrefix?: string; // default: 'docs'
    addBearerAuth?: boolean; // default: true
  },
) {
  const routePrefix = opts.routePrefix ?? 'docs';
  const addBearer = opts.addBearerAuth ?? true;

  // const isProd = process.env.NODE_ENV === 'production';
  // const baseUrl = isProd
  //   ? 'https://nestjs-tutorial.darmist.com/backend'
  //   : 'http://localhost:3501';

  const builder = new DocumentBuilder()
    .setTitle(opts.title)
    .setDescription(opts.description)
    .setVersion(opts.version ?? '1.0.0')
    .addServer('https://aero.darmist.com/backend', 'Production Server')
    .addServer('http://localhost:3501', 'Local Development');
  // .addServer(baseUrl, isProd ? 'Production Server' : 'Local Development');

  // JWT Bearer (access token)
  if (addBearer) {
    builder.addBearerAuth(
      {
        type: 'http',
        scheme: 'bearer',
        bearerFormat: 'JWT',
        name: 'Authorization',
        description:
          'Use a valid **access token**.\n\nFormat: `Bearer <ACCESS_TOKEN>`',
        in: 'header',
      },
      'bearer',
    );
  }

  // You can add global servers if needed, e.g. local dev
  // builder.addServer('http://localhost:3501', 'Local (Gateway)');

  const config = builder.build();

  const document = SwaggerModule.createDocument(app, config, {
    // You can whitelist modules or extra models here if needed
    // include: [],
    // deepScanRoutes: true,
  });

  SwaggerModule.setup(routePrefix, app, document, {
    jsonDocumentUrl: `${routePrefix}/json`,
    explorer: true,
    customSiteTitle: `${opts.title} — API Docs`,
  });

  // Export OpenAPI JSON to /openapi folder at the app root
  try {
    const outDir = join(process.cwd(), 'openapi');
    if (!existsSync(outDir)) mkdirSync(outDir, { recursive: true });
    const file = join(outDir, `${kebab(opts.title)}.json`);
    writeFileSync(file, JSON.stringify(document, null, 2));

    console.log(`🧾 OpenAPI exported: ${file}`);
  } catch (e) {
    console.warn('OpenAPI export failed:', (e as Error).message);
  }

  console.log(`📘 Swagger UI: /${routePrefix}  (json: /${routePrefix}/json)`);
}

function kebab(name: string) {
  return (name || 'api')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/(^-|-$)/g, '');
}
```

`libs/common-lib/src/decorators/api-tenant-header.decorator.ts`
```typescript
import { applyDecorators } from '@nestjs/common';
import { ApiHeader } from '@nestjs/swagger';

/**
 * Adds the tenant header to an endpoint or controller.
 *
 * For Gateway controllers, this is usually required on all endpoints,
 * including PUBLIC ones.
 */
export function ApiTenantHeader(required = true) {
  return applyDecorators(
    ApiHeader({
      name: 'x-tenant-id',
      description: 'Tenant identifier (e.g., "darmist1")',
      required,
      schema: { type: 'string', example: 'darmist1' },
    }),
  );
}
```

(Optional) Annotate `ApiListQueryDto` for Swagger
If your `ListQueryDto` lives in `common-lib`, annotate it for better docs.

`libs/common-lib/src/dto/query.dto.ts` (🔁 update if exists)
```typescript
import { IsInt, IsOptional, IsString, Min, IsNumber } from 'class-validator';
import { Transform } from 'class-transformer';
import { ApiPropertyOptional } from '@nestjs/swagger';

export class ListQueryDto {
  @ApiPropertyOptional({ description: 'Page number (1-based)', example: 1 })
  @IsOptional()
  @Transform(({ value }) => Number(value))
  @IsInt()
  @Min(1)
  page?: number = 1;

  @ApiPropertyOptional({ description: 'Page size (max 100)', example: 10 })
  @IsOptional()
  @Transform(({ value }) => Number(value))
  @IsInt()
  @Min(1)
  pageSize?: number = 10;

  @ApiPropertyOptional({ description: 'Search text', example: 'shirt' })
  @IsOptional()
  @IsString()
  q?: string;

  @ApiPropertyOptional({
    description: 'Filter by status',
    example: 'PUBLISHED',
  })
  @IsOptional()
  @IsString()
  status?: string; // DRAFT|PUBLISHED|ARCHIVED

  @ApiPropertyOptional({
    description: 'Filter by category id',
    example: 'CAT-001',
  })
  @IsOptional()
  @IsString()
  categoryId?: string;

  @ApiPropertyOptional({ description: 'Minimum price', example: 500 })
  @IsOptional()
  @Transform(({ value }) => Number(value))
  @IsNumber()
  minPrice?: number;

  @ApiPropertyOptional({ description: 'Maximum price', example: 5000 })
  @IsOptional()
  @Transform(({ value }) => Number(value))
  @IsNumber()
  maxPrice?: number;

  @ApiPropertyOptional({
    description: 'Sort: field:asc|desc',
    example: 'createdAt:desc',
  })
  @IsOptional()
  @IsString()
  sort?: string; // "createdAt:desc" | "basePrice:asc" | etc.
}
```

Export from `common-lib`
`libs/common-lib/src/index.ts` (🔁 update)
```typescript
export * from './common-lib.module';
export * from './common-lib.service';

export * from './response.util';
export * from './dto/query.dto';
export * from './swagger';
export * from './decorators/api-tenant-header.decorator';
```

## ⚙️ 3) Annotate DTOs (Product) so Swagger shows field-level info
Update your Product DTOs with `@ApiProperty` / `@ApiPropertyOptional` and enum references.

`apps/product-service/src/dto/create-product.dto.ts` (🔁 update)
```typescript
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import {
  IsArray,
  IsEnum,
  IsNotEmpty,
  IsNumber,
  IsOptional,
  IsString,
  Matches,
  Min,
  ValidateNested,
} from 'class-validator';
import { Type } from 'class-transformer';
import { GarmentType, ProductStatus } from '../schemas/product.schema';

class CustomOptionDto {
  @ApiProperty({
    example: 'color',
    description: 'Option key (internal identifier)',
  })
  @IsString()
  @IsNotEmpty()
  key!: string;

  @ApiProperty({ example: 'Color', description: 'Human-readable label' })
  @IsString()
  @IsNotEmpty()
  label!: string;

  @ApiProperty({ example: 'blue', description: 'Option value' })
  @IsString()
  @IsNotEmpty()
  value!: string;
}

export class CreateProductDto {
  @ApiProperty({
    example: 'Tailored Shirt',
    description: 'Human-readable product name',
  })
  @IsString()
  @IsNotEmpty()
  name!: string;

  @ApiProperty({
    example: 'tailored-shirt',
    description: 'URL-friendly unique slug',
  })
  @IsString()
  @Matches(/^[a-z0-9-]+$/, {
    message: 'Slug must be lowercase alphanumeric with hyphens',
  })
  slug!: string;

  @ApiProperty({
    example: 'SKU-001',
    description: 'External/internal SKU, unique per tenant DB',
  })
  @IsString()
  @Matches(/^[A-Z0-9-]+$/, {
    message: 'SKU must be uppercase alphanumeric with hyphens',
  })
  sku!: string;

  @ApiProperty({
    enum: GarmentType,
    example: 'SHIRT',
    description: 'Garment type/code',
  })
  @IsEnum(GarmentType)
  garment!: GarmentType;

  @ApiPropertyOptional({
    example: 'Slim fit cotton shirt',
    description: 'Product description',
  })
  @IsOptional()
  @IsString()
  description?: string;

  @ApiPropertyOptional({
    type: [String],
    example: ['formal', 'slim-fit'],
    description: 'Product tags',
  })
  @IsOptional()
  @IsArray()
  tags?: string[];

  @ApiProperty({
    example: 1290,
    description: 'Base price in SEK (Swedish Krona)',
  })
  @IsNumber()
  @Min(0)
  basePrice!: number;

  @ApiPropertyOptional({
    example: 100,
    description: 'Available stock quantity',
  })
  @IsOptional()
  @IsNumber()
  stockQuantity?: number;

  @ApiPropertyOptional({
    enum: ProductStatus,
    default: ProductStatus.DRAFT,
    description: 'Product lifecycle status',
  })
  @IsOptional()
  @IsEnum(ProductStatus)
  status?: ProductStatus;

  @ApiPropertyOptional({
    type: [String],
    example: ['https://cdn.site.com/img1.png'],
    description: 'Image URLs',
  })
  @IsOptional()
  @IsArray()
  images?: string[];

  @ApiPropertyOptional({
    type: [CustomOptionDto],
    description: 'Custom product options',
  })
  @IsOptional()
  @ValidateNested({ each: true })
  @Type(() => CustomOptionDto)
  customOptions?: CustomOptionDto[];
}
```

## ⚙️ 4) Add Swagger bootstrap to each service’s `main.ts`
We’ll conditionally enable Swagger in non-production environments. You can change route prefix per service if you prefer (`/docs`, `/docs-auth`, etc.).

### 4.1 API Gateway
`apps/api-gateway/src/main.ts` (🔁 update)
```typescript
import { NestFactory } from '@nestjs/core';
import { Logger } from '@nestjs/common';
import * as path from 'node:path';
import { ApiGatewayModule } from './api-gateway.module';
import { setupSwagger } from '@app/common-lib';

// Dynamically infer service name from directory name
const serviceName = path.basename(path.dirname(__filename)) || 'service';

async function bootstrap() {
  const ENV_PREFIX = serviceName.toUpperCase().replace(/-/g, '_');
  const httpPort = Number(process.env[`${ENV_PREFIX}_HTTP_PORT`]) || 3000;

  // Create HTTP app
  const app = await NestFactory.create(ApiGatewayModule);

  // // Attach TCP microservice
  // app.connectMicroservice<MicroserviceOptions>({
  //   transport: Transport.TCP,
  //   options: { host: '0.0.0.0', port: tcpPort },
  // });

  // Swagger only in non-production
  if (process.env.NODE_ENV !== 'production') {
    setupSwagger(app, {
      title: 'API Gateway',
      description: 'Public HTTP entrypoint routing to microservices (TCP).',
      version: '1.0.0',
      routePrefix: 'docs', // → http://localhost:3501/docs
      addBearerAuth: true,
    });
  }

  await app.startAllMicroservices();
  await app.listen(httpPort);

  const logger = new Logger(serviceName);
  logger.log(
    `\n🚀  ${serviceName} ready!\n` +
      `    REST: http://localhost:${httpPort}\n` +
      `    ENV : ${process.env.NODE_ENV}`,
  );
}
bootstrap();
```

### 4.2 Product Service
`apps/product-service/src/main.ts` (🔁 update)
```typescript
import { NestFactory } from '@nestjs/core';
import { MicroserviceOptions, Transport } from '@nestjs/microservices';
import { Logger } from '@nestjs/common';
import * as path from 'node:path';
import { ProductServiceModule } from './product-service.module';
import { setupSwagger } from '@app/common-lib';

// Dynamically infer service name from directory name
const serviceName = path.basename(path.dirname(__filename)) || 'service';

async function bootstrap() {
  const ENV_PREFIX = serviceName.toUpperCase().replace(/-/g, '_');
  const httpPort = Number(process.env[`${ENV_PREFIX}_HTTP_PORT`]) || 3000;
  const tcpPort = Number(process.env[`${ENV_PREFIX}_TCP_PORT`]) || 4000;

  console.log(`${ENV_PREFIX}_HTTP_PORT`);

  // Create HTTP app
  const app = await NestFactory.create(ProductServiceModule);

  // Attach TCP microservice
  app.connectMicroservice<MicroserviceOptions>({
    transport: Transport.TCP,
    options: { host: '0.0.0.0', port: tcpPort },
  });

  // Swagger
  if (process.env.NODE_ENV !== 'production') {
    setupSwagger(app, {
      title: 'Product Service',
      description:
        'Per-tenant product catalog (HTTP uses TenantMiddleware). TCP for Gateway.',
      version: '1.0.0',
      routePrefix: 'docs', // http://localhost:3005/docs
      addBearerAuth: true,
    });
  }

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

## ⚙️ 5) Swagger decorators on Gateway controllers (Products)
Add rich metadata so API consumers see security, headers, queries and responses.
*   Public endpoints: don’t add `@ApiBearerAuth()`.
*   Protected endpoints: add `@ApiBearerAuth('bearer')` + roles in description.

`apps/api-gateway/src/product-gateway.controller.ts` (🔁 update)
```typescript
import {
  BadRequestException,
  Body,
  Controller,
  Delete,
  Get,
  Headers,
  Inject,
  Param,
  Patch,
  Post,
  Query,
  Req,
} from '@nestjs/common';
import { ClientProxy } from '@nestjs/microservices';
import { firstValueFrom, timeout, catchError, throwError } from 'rxjs';
import { ListQueryDto } from '@app/common-lib';
import { CreateProductDto } from '../../product-service/src/dto/create-product.dto';
import { UpdateProductDto } from '../../product-service/src/dto/update-product.dto';
import { Public, Roles } from '@app/auth-lib';
import {
  ApiBadRequestResponse,
  ApiBearerAuth,
  ApiBody,
  ApiConflictResponse,
  ApiCreatedResponse, ApiForbiddenResponse, ApiInternalServerErrorResponse, ApiNotFoundResponse, ApiOkResponse,
  ApiOperation, ApiParam, ApiQuery,
  ApiUnauthorizedResponse,
} from '@nestjs/swagger';

@Controller('gateway/products')
export class ProductGatewayController {
  constructor(
    @Inject('PRODUCT_SERVICE') private readonly productClient: ClientProxy,
  ) {}

  private async sendSafe<T>(cmd: string, payload: any): Promise<T> {
    try {
      return await firstValueFrom(
        this.productClient.send<T>({ cmd }, payload).pipe(
          timeout(10000),
          catchError((error) => {
            const message =
              error?.message ||
              error?.response?.message ||
              'Product service error';
            const errors = error?.response?.errors;
            return throwError(
              () => new BadRequestException({ message, errors }),
            );
          }),
        ),
      );
    } catch (unexpected: any) {
      throw new BadRequestException(
        unexpected?.response || {
          message: unexpected?.message || 'Product service error',
        },
      );
    }
  }

  // ───────────────────────────────
  // PROTECTED: Create (manager/admin)
  // ───────────────────────────────
  @Roles('manager', 'admin')
  @Post()
  @ApiBearerAuth('bearer')
  @ApiOperation({
    summary: 'Create Product (Manager/Admin)',
    description: `
Creates a new **product record** within a tenant's catalog.  
Only users with **manager** or **admin** roles are authorized.

### 🧩 Flow
1. Requires a valid **JWT token** and **x-tenant-id** header.  
2. Accepts full product details such as SKU, slug, name, price, category, etc.  
3. Automatically records creator and updater metadata.  
4. Clears all product-related caches for the tenant after creation.

### ⚠️ Notes
- Product **slug** and **SKU** must be unique per tenant.  
- Creation automatically logs metadata for auditing (createdBy, updatedBy).  
- Cached product lists are invalidated after successful creation.
`,
  })
  @ApiBody({
    type: CreateProductDto,
    examples: {
      validExample: {
        summary: 'Example product creation request',
        value: {
          name: 'Formal Cotton Shirt',
          sku: 'SHIRT-001',
          slug: 'formal-cotton-shirt',
          category: 'SHIRTS',
          price: 59.99,
          currency: 'USD',
          description: 'A premium cotton shirt for office wear.',
          stock: 100,
          images: [
            'https://cdn.example.com/products/shirt-001-front.jpg',
            'https://cdn.example.com/products/shirt-001-back.jpg',
          ],
        },
      },
    },
  })
  @ApiCreatedResponse({
    description: 'Product created successfully',
    schema: {
      example: {
        message: 'Product has been created successfully.',
        data: {
          _id: 'uuid',
          name: 'Formal Cotton Shirt',
          sku: 'SHIRT-001',
          slug: 'formal-cotton-shirt',
          category: 'SHIRTS',
          price: 59.99,
          stock: 100,
          createdBy: 'manager.jane',
          createdAt: '2025-10-11T12:30:45.123Z',
        },
        meta: { status: 'success', code: 'PRODUCT_CREATED' },
        ts: '2025-10-11T12:30:45.123Z',
      },
    },
  })
  @ApiConflictResponse({
    description: 'Duplicate SKU or slug',
    schema: {
      oneOf: [
        {
          example: {
            message: 'Product slug already exists. Please choose another.',
            data: null,
            meta: { status: 'error', code: 'DUPLICATE_SLUG' },
            ts: '2025-10-11T12:30:45.123Z',
          },
        },
        {
          example: {
            message: 'Product SKU already exists. Please use a unique SKU.',
            data: null,
            meta: { status: 'error', code: 'DUPLICATE_SKU' },
            ts: '2025-10-11T12:30:45.123Z',
          },
        },
      ],
    },
  })
  @ApiUnauthorizedResponse({
    description: 'Missing or invalid JWT access token',
    schema: {
      example: {
        message: 'Unauthorized: Missing or invalid access token',
        data: null,
        meta: { status: 'error', code: 'UNAUTHORIZED' },
        ts: '2025-10-11T12:30:45.123Z',
      },
    },
  })
  @ApiForbiddenResponse({
    description: 'User does not have required manager/admin role',
    schema: {
      example: {
        message: 'Access denied: Insufficient role privileges',
        data: null,
        meta: { status: 'error', code: 'FORBIDDEN' },
        ts: '2025-10-11T12:30:45.123Z',
      },
    },
  })
  @ApiBadRequestResponse({
    description: 'Missing tenant ID or invalid input data',
    schema: {
      example: {
        message: 'x-tenant-id is required',
        data: null,
        meta: { status: 'error', code: 'TENANT_ID_MISSING' },
        ts: '2025-10-11T12:30:45.123Z',
      },
    },
  })
  @ApiInternalServerErrorResponse({
    description: 'Unexpected error during product creation',
    schema: {
      example: {
        message: 'Failed to create product due to an internal error.',
        data: null,
        meta: {
          status: 'error',
          code: 'INTERNAL_ERROR',
          error: 'Database write failure',
        },
        ts: '2025-10-11T12:30:45.123Z',
      },
    },
  })
  async create(
    @Req() req: any,
    @Headers('x-tenant-id') tenantIdentifier: string,
    @Body() createProductDto: CreateProductDto,
  ) {
    if (!tenantIdentifier)
      throw new BadRequestException('x-tenant-id is required');

    const actor = {
      id: req?.user?.sub,
      username: req?.user?.username ?? req?.actor?.username,
    };

    const result = await this.sendSafe<any>('product.create', {
      tenantId: tenantIdentifier,
      dto: createProductDto,
      actor,
    });
    return result;
  }

  // ───────────────────────────────
  // Check Product SKU Availability (API Gateway)
  // ───────────────────────────────
  @Public()
  @Get('check-sku/:sku')
  @ApiOperation({
    summary: 'Check Product SKU Availability (Tenant-Aware)',
    description: `
Checks whether a **product SKU** is already in use under the specified tenant.

### 🧩 Flow
1. Validates **x-tenant-id** (must be provided in header).  
2. Checks the SKU against the tenant's product database.  
3. Returns availability status.

### ⚠️ Important Notes
- The **x-tenant-id** header is mandatory to identify the tenant environment.
- If the SKU already exists, the endpoint will return a clear error message.
- This does **not** reserve the SKU — it only checks existence.
`,
  })
  @ApiParam({
    name: 'sku',
    required: true,
    description: 'Product SKU to check availability for',
    example: 'SKU-12345',
  })
  @ApiOkResponse({
    description: 'SKU is available',
    schema: {
      example: {
        message: 'This SKU is available.',
        data: {
          status: 'success',
          code: 'SKU_AVAILABLE',
          data: { available: true },
        },
        ts: '2025-10-13T14:00:00.000Z',
      },
    },
  })
  @ApiConflictResponse({
    description: 'SKU already taken',
    schema: {
      example: {
        message: 'This SKU is already in use.',
        data: {
          status: 'error',
          code: 'SKU_TAKEN',
          data: { available: false },
        },
        ts: '2025-10-13T14:00:00.000Z',
      },
    },
  })
  @ApiBadRequestResponse({
    description: 'Missing tenant ID or invalid input',
    schema: {
      example: {
        message: 'x-tenant-id is required',
        statusCode: 400,
        error: 'Bad Request',
      },
    },
  })
  @ApiInternalServerErrorResponse({
    description: 'Unexpected server error during SKU check',
    schema: {
      example: {
        message:
          'SKU check failed due to a system error. Please try again later.',
        data: {
          status: 'error',
          code: 'INTERNAL_ERROR',
          error: 'Database connection lost',
        },
        ts: '2025-10-13T14:00:00.000Z',
      },
    },
  })
  async checkSkuAvailability(
    @Headers('x-tenant-id') tenantId: string,
    @Param('sku') sku: string,
  ) {
    if (!tenantId) throw new BadRequestException('x-tenant-id is required');
    const result = await this.sendSafe<any>('product.check-sku', {
      tenantId,
      sku,
    });
    return result;
  }

  // ───────────────────────────────
  // Check Product Slug Availability (API Gateway)
  // ───────────────────────────────
  @Public()
  @Get('check-slug/:slug')
  @ApiOperation({
    summary: 'Check Product Slug Availability (Tenant-Aware)',
    description: `
Checks whether a **product slug** is already in use under the specified tenant.

### 🧩 Flow
1. Validates **x-tenant-id** (must be provided in header).  
2. Checks the slug against the tenant's product database.  
3. Returns availability status.

### ⚠️ Important Notes
- The **x-tenant-id** header is mandatory to identify the tenant environment.
- If the slug already exists, the endpoint will return a clear error message.
- This does **not** reserve the slug — it only checks existence.
`,
  })
  @ApiParam({
    name: 'slug',
    required: true,
    description: 'Product slug to check availability for',
    example: 'new-summer-shirt',
  })
  @ApiOkResponse({
    description: 'Slug is available',
    schema: {
      example: {
        message: 'This product slug is available.',
        data: {
          status: 'success',
          code: 'SLUG_AVAILABLE',
          data: { available: true },
        },
        ts: '2025-10-13T14:00:00.000Z',
      },
    },
  })
  @ApiConflictResponse({
    description: 'Slug already taken',
    schema: {
      example: {
        message: 'This product slug is already in use.',
        data: {
          status: 'error',
          code: 'SLUG_TAKEN',
          data: { available: false },
        },
        ts: '2025-10-13T14:00:00.000Z',
      },
    },
  })
  @ApiBadRequestResponse({
    description: 'Missing tenant ID or invalid input',
    schema: {
      example: {
        message: 'x-tenant-id is required',
        statusCode: 400,
        error: 'Bad Request',
      },
    },
  })
  @ApiInternalServerErrorResponse({
    description: 'Unexpected server error during slug check',
    schema: {
      example: {
        message:
          'Slug check failed due to a system error. Please try again later.',
        data: {
          status: 'error',
          code: 'INTERNAL_ERROR',
          error: 'Database connection lost',
        },
        ts: '2025-10-13T14:00:00.000Z',
      },
    },
  })
  async checkSlugAvailability(
    @Headers('x-tenant-id') tenantId: string,
    @Param('slug') slug: string,
  ) {
    if (!tenantId) throw new BadRequestException('x-tenant-id is required');
    const result = await this.sendSafe<any>('product.check-slug', {
      tenantId,
      slug,
    });
    return result;
  }

  // ───────────────────────────────
  // PUBLIC: List
  // ───────────────────────────────
  @Public()
  @Get()
  @ApiOperation({
    summary: 'List Products (Public, Paginated)',
    description: `
Retrieves a **paginated and filterable** list of products.  
This endpoint is **public**, meaning no authentication is required.

### 🧩 Flow
1. Requires the **x-tenant-id** header to identify which tenant's catalog to query.  
2. Supports **pagination**, **search**, **sorting**, and **status-based filtering**.  
3. Uses **Redis caching** to speed up repeated queries.  
4. Returns products along with pagination metadata.

### ⚙️ Query Parameters
| Parameter | Type | Description | Example |
|------------|------|-------------|----------|
| q | string | Search keyword (matches name, description, SKU, etc.) | shirt |
| page | number | Page number (default: 1) | 1 |
| pageSize | number | Number of results per page (default: 10) | 10 |
| sort | string | Sort by field (e.g., price:asc, createdAt:desc) | createdAt:desc |
| status | string | Filter by status (e.g., PUBLISHED, DRAFT) | PUBLISHED |

### ⚠️ Notes
- Cached responses are valid for a limited time (TTL-based).  
- Results are sorted and paginated efficiently using MongoDB indices.  
- Intended for **storefronts, search results, and product listing pages**.
`,
  })
  @ApiQuery({ name: 'q', required: false, example: 'shirt' })
  @ApiQuery({ name: 'page', required: false, example: 1 })
  @ApiQuery({ name: 'pageSize', required: false, example: 10 })
  @ApiQuery({ name: 'sort', required: false, example: 'createdAt:desc' })
  @ApiQuery({ name: 'status', required: false, example: 'PUBLISHED' })
  @ApiOkResponse({
    description: 'Paginated list of products returned successfully',
    schema: {
      example: {
        message: 'Products fetched successfully.',
        data: [
          {
            _id: 'uuid',
            name: 'Formal Cotton Shirt',
            sku: 'SHIRT-001',
            slug: 'formal-cotton-shirt',
            price: 59.99,
            category: 'SHIRTS',
            stock: 120,
            status: 'PUBLISHED',
            createdAt: '2025-10-09T12:45:30.123Z',
          },
          {
            _id: 'uuid',
            name: 'Slim Fit Trousers',
            sku: 'PANT-002',
            slug: 'slim-fit-trousers',
            price: 69.99,
            category: 'PANTS',
            stock: 90,
            status: 'PUBLISHED',
            createdAt: '2025-10-08T14:20:10.456Z',
          },
        ],
        meta: {
          total: 2,
          page: 1,
          pageSize: 10,
          totalPages: 1,
          status: 'success',
          code: 'PRODUCTS_FETCHED',
        },
        ts: '2025-10-11T12:30:45.123Z',
      },
    },
  })
  @ApiBadRequestResponse({
    description: 'Missing tenant ID or invalid query parameters',
    schema: {
      example: {
        message: 'x-tenant-id is required',
        data: null,
        meta: { status: 'error', code: 'TENANT_ID_MISSING' },
        ts: '2025-10-11T12:30:45.123Z',
      },
    },
  })
  @ApiInternalServerErrorResponse({
    description: 'Unexpected error while fetching product list',
    schema: {
      example: {
        message: 'Failed to fetch product list due to an internal error.',
        data: null,
        meta: {
          status: 'error',
          code: 'INTERNAL_ERROR',
          error: 'Redis connection failed',
        },
        ts: '2025-10-11T12:30:45.123Z',
      },
    },
  })
  async list(
    @Headers('x-tenant-id') tenantIdentifier: string,
    @Query() listQueryDto: ListQueryDto,
  ) {
    if (!tenantIdentifier)
      throw new BadRequestException('x-tenant-id is required');

    const result = await this.sendSafe<any>('product.list', {
      tenantId: tenantIdentifier,
      q: listQueryDto,
    });
    return result;
  }

  // ───────────────────────────────
  // PUBLIC: Get by ID
  // ───────────────────────────────
  @Public()
  @Get(':id')
  @ApiOperation({
    summary: 'Get Product by ID (Public)',
    description: `
Fetches detailed information for a single **product record** based on its unique ID.  
This endpoint is **public**, requiring no authentication.

### 🧩 Flow
1. Requires **x-tenant-id** header to identify the tenant database.  
2. Retrieves the product details by ID.  
3. Uses **Redis caching** to optimize performance for frequent lookups.  
4. Returns full product details including pricing, images, and metadata.

### ⚠️ Notes
- Cached data is refreshed every few minutes (TTL-based).  
- Deleted or unpublished products are excluded.  
- Suitable for product detail pages and public APIs.
`,
  })
  @ApiParam({
    name: 'id',
    description: 'Unique product identifier (UUID or Mongo ObjectId)',
    example: '66f1b0b1a2345c9b1b234567',
  })
  @ApiOkResponse({
    description: 'Product details retrieved successfully',
    schema: {
      example: {
        message: 'Product fetched successfully.',
        data: {
          _id: '66f1b0b1a2345c9b1b234567',
          name: 'Classic Linen Shirt',
          sku: 'SHIRT-004',
          slug: 'classic-linen-shirt',
          price: 79.99,
          currency: 'USD',
          category: 'SHIRTS',
          stock: 50,
          status: 'PUBLISHED',
          description: 'Premium linen shirt for summer collection.',
          images: [
            'https://cdn.example.com/products/shirt-004-front.jpg',
            'https://cdn.example.com/products/shirt-004-back.jpg',
          ],
          createdAt: '2025-10-09T12:45:30.123Z',
        },
        meta: { status: 'success', code: 'PRODUCT_FETCHED' },
        ts: '2025-10-11T12:30:45.123Z',
      },
    },
  })
  @ApiNotFoundResponse({
    description: 'Product not found or deleted',
    schema: {
      example: {
        message: 'Product not found.',
        data: null,
        meta: {
          status: 'error',
          code: 'PRODUCT_NOT_FOUND',
          id: '66f1b0b1a2345c9b1b234567',
        },
        ts: '2025-10-11T12:30:45.123Z',
      },
    },
  })
  @ApiBadRequestResponse({
    description: 'Missing tenant ID or invalid parameters',
    schema: {
      example: {
        message: 'x-tenant-id is required',
        data: null,
        meta: { status: 'error', code: 'TENANT_ID_MISSING' },
        ts: '2025-10-11T12:30:45.123Z',
      },
    },
  })
  @ApiInternalServerErrorResponse({
    description: 'Unexpected server or database error',
    schema: {
      example: {
        message: 'Failed to fetch product due to an internal error.',
        data: null,
        meta: {
          status: 'error',
          code: 'INTERNAL_ERROR',
          error: 'MongoDB connection timeout',
        },
        ts: '2025-10-11T12:30:45.123Z',
      },
    },
  })
  async getById(
    @Headers('x-tenant-id') tenantIdentifier: string,
    @Param('id') productIdentifier: string,
  ) {
    if (!tenantIdentifier)
      throw new BadRequestException('x-tenant-id is required');

    const result = await this.sendSafe<any>('product.getById', {
      tenantId: tenantIdentifier,
      id: productIdentifier,
    });
    return result;
  }

  // ───────────────────────────────
  // PUBLIC: Get by Slug
  // ───────────────────────────────
  @Public()
  @Get('slug/:slug')
  @ApiOperation({
    summary: 'Get Product by Slug (Public)',
    description: `
Fetches detailed product information based on its **slug**.  
This endpoint is **public** and does not require authentication.

### 🧩 Flow
1. Requires the **x-tenant-id** header to identify the tenant catalog.  
2. Searches for the product by its slug.  
3. Uses **Redis caching** for faster subsequent lookups.  
4. Returns full product details including name, price, description, and images.

### ⚠️ Notes
- Cached results are valid for a limited TTL period.  
- Deleted or unpublished products are excluded.  
- Ideal for product detail pages on storefronts.
`,
  })
  @ApiParam({
    name: 'slug',
    description: 'Unique product slug used for public display URLs',
    example: 'tailored-shirt',
  })
  @ApiOkResponse({
    description: 'Product details retrieved successfully',
    schema: {
      example: {
        message: 'Product fetched successfully.',
        data: {
          _id: 'uuid',
          name: 'Tailored Cotton Shirt',
          slug: 'tailored-shirt',
          sku: 'TSHIRT-101',
          price: 79.99,
          currency: 'USD',
          category: 'SHIRTS',
          stock: 50,
          status: 'PUBLISHED',
          description: 'Perfectly tailored cotton shirt for formal occasions.',
          images: [
            'https://cdn.example.com/products/tailored-shirt-front.jpg',
            'https://cdn.example.com/products/tailored-shirt-back.jpg',
          ],
          createdAt: '2025-10-09T12:45:30.123Z',
        },
        meta: { status: 'success', code: 'PRODUCT_FETCHED' },
        ts: '2025-10-11T12:30:45.123Z',
      },
    },
  })
  @ApiNotFoundResponse({
    description: 'Product not found or deleted',
    schema: {
      example: {
        message: 'Product not found.',
        data: null,
        meta: {
          status: 'error',
          code: 'PRODUCT_NOT_FOUND',
          slug: 'tailored-shirt',
        },
        ts: '2025-10-11T12:30:45.123Z',
      },
    },
  })
  @ApiBadRequestResponse({
    description: 'Missing tenant header or invalid request',
    schema: {
      example: {
        message: 'x-tenant-id is required',
        data: null,
        meta: { status: 'error', code: 'TENANT_ID_MISSING' },
        ts: '2025-10-11T12:30:45.123Z',
      },
    },
  })
  @ApiInternalServerErrorResponse({
    description: 'Unexpected error while fetching product by slug',
    schema: {
      example: {
        message: 'Failed to fetch product due to an internal error.',
        data: null,
        meta: {
          status: 'error',
          code: 'INTERNAL_ERROR',
          error: 'Redis connection timeout',
        },
        ts: '2025-10-11T12:30:45.123Z',
      },
    },
  })
  async getBySlug(
    @Headers('x-tenant-id') tenantIdentifier: string,
    @Param('slug') slug: string,
  ) {
    if (!tenantIdentifier)
      throw new BadRequestException('x-tenant-id is required');

    const result = await this.sendSafe<any>('product.getBySlug', {
      tenantId: tenantIdentifier,
      slug,
    });
    return result;
  }

  // ───────────────────────────────
  // PROTECTED: Update (manager/admin)
  // ───────────────────────────────
  @Roles('manager', 'admin')
  @Patch(':id')
  @ApiBearerAuth('bearer')
  @ApiOperation({
    summary: 'Update Product (Manager/Admin)',
    description: `
Updates an existing **product record** within the tenant catalog.  
Only users with **manager** or **admin** roles are authorized.

### 🧩 Flow
1. Requires a valid **JWT token** and **x-tenant-id** header.  
2. Finds the product by its **ID** and applies the provided updates.  
3. Updates metadata fields (
updatedBy
, 
updatedAt
).
4. Clears all cached product data for the tenant after successful update.

### ⚠️ Notes
- Partial updates are supported.  
- Duplicate **slug** or **SKU** values are not allowed.  
- All updates are logged for audit purposes.
`,
  })
  @ApiParam({
    name: 'id',
    description: 'Unique product identifier (UUID)',
    example: 'b3a1f2d4-569c-4a11-b25a-6f3c2b28c1c7',
  })
  @ApiBody({
    description: 'Fields to update in the product',
    type: UpdateProductDto,
    examples: {
      validExample: {
        summary: 'Example update request',
        value: {
          name: 'Slim Fit Cotton Shirt',
          price: 64.99,
          stock: 80,
          description: 'Updated product description with new pricing.',
        },
      },
    },
  })
  @ApiOkResponse({
    description: 'Product updated successfully',
    schema: {
      example: {
        message: 'Product has been updated successfully.',
        data: {
          _id: 'b3a1f2d4-569c-4a11-b25a-6f3c2b28c1c7',
          name: 'Slim Fit Cotton Shirt',
          sku: 'SHIRT-001',
          slug: 'slim-fit-cotton-shirt',
          price: 64.99,
          stock: 80,
          updatedBy: 'manager.jane',
          updatedAt: '2025-10-11T12:30:45.123Z',
        },
        meta: { status: 'success', code: 'PRODUCT_UPDATED' },
        ts: '2025-10-11T12:30:45.123Z',
      },
    },
  })
  @ApiConflictResponse({
    description: 'Duplicate SKU or slug during update',
    schema: {
      oneOf: [
        {
          example: {
            message: 'Product slug already exists.',
            data: null,
            meta: { status: 'error', code: 'DUPLICATE_SLUG' },
            ts: '2025-10-11T12:30:45.123Z',
          },
        },
        {
          example: {
            message: 'Product SKU already exists.',
            data: null,
            meta: { status: 'error', code: 'DUPLICATE_SKU' },
            ts: '2025-10-11T12:30:45.123Z',
          },
        },
      ],
    },
  })
  @ApiNotFoundResponse({
    description: 'Product not found or deleted',
    schema: {
      example: {
        message: 'Product not found.',
        data: null,
        meta: {
          status: 'error',
          code: 'PRODUCT_NOT_FOUND',
          id: 'b3a1f2d4-569c-4a11-b25a-6f3c2b28c1c7',
        },
        ts: '2025-10-11T12:30:45.123Z',
      },
    },
  })
  @ApiUnauthorizedResponse({
    description: 'Missing or invalid JWT access token',
    schema: {
      example: {
        message: 'Unauthorized: Missing or invalid access token',
        data: null,
        meta: { status: 'error', code: 'UNAUTHORIZED' },
        ts: '2025-10-11T12:30:45.123Z',
      },
    },
  })
  @ApiForbiddenResponse({
    description: 'User lacks manager/admin privileges',
    schema: {
      example: {
        message: 'Access denied: Insufficient role privileges',
        data: null,
        meta: { status: 'error', code: 'FORBIDDEN' },
        ts: '2025-10-11T12:30:45.123Z',
      },
    },
  })
  @ApiBadRequestResponse({
    description: 'Missing tenant ID or invalid request body',
    schema: {
      example: {
        message: 'x-tenant-id is required',
        data: null,
        meta: { status: 'error', code: 'TENANT_ID_MISSING' },
        ts: '2025-10-11T12:30:45.123Z',
      },
    },
  })
  @ApiInternalServerErrorResponse({
    description: 'Unexpected error while updating product',
    schema: {
      example: {
        message: 'Failed to update product due to an internal error.',
        data: null,
        meta: {
          status: 'error',
          code: 'INTERNAL_ERROR',
          error: 'MongoDB validation error',
        },
        ts: '2025-10-11T12:30:45.123Z',
      },
    },
  })
  async update(
    @Req() req: any,
    @Headers('x-tenant-id') tenantIdentifier: string,
    @Param('id') productIdentifier: string,
    @Body() updateProductDto: UpdateProductDto,
  ) {
    if (!tenantIdentifier)
      throw new BadRequestException('x-tenant-id is required');

    const actor = {
      id: req?.user?.sub,
      username: req?.user?.username ?? req?.actor?.username,
    };

    const result = await this.sendSafe<any>('product.update', {
      tenantId: tenantIdentifier,
      id: productIdentifier,
      dto: updateProductDto,
      actor,
    });
    return result;
  }

  // ───────────────────────────────
  // PROTECTED: Change Status (manager/admin)
  // ───────────────────────────────
  @Roles('manager', 'admin')
  @Patch(':id/status')
  @ApiBearerAuth('bearer')
  @ApiOperation({
    summary: 'Change Product Status (Manager/Admin)',
    description: `
Allows **manager** or **admin** to change the status of a product.  
Statuses may include: 
PUBLISHED
, 
DRAFT
, or 
ARCHIVED
.

### 🧩 Flow
1. Requires **JWT token** and **x-tenant-id** header.  
2. Updates only the status field and logs the actor.  
3. Clears cached data for consistency.

### ⚠️ Notes
- Commonly used to toggle product visibility.
- All status updates are recorded with metadata.
`,
  })
  @ApiParam({ name: 'id', description: 'Product ID', example: 'uuid' })
  @ApiBody({
    schema: {
      properties: { status: { type: 'string', example: 'PUBLISHED' } },
    },
  })
  @ApiOkResponse({
    description: 'Product status updated successfully',
    schema: {
      example: {
        message: 'Product status has been updated successfully.',
        data: { id: 'uuid', status: 'PUBLISHED' },
        meta: { status: 'success', code: 'PRODUCT_STATUS_UPDATED' },
        ts: '2025-10-11T12:30:45.123Z',
      },
    },
  })
  @ApiNotFoundResponse({
    description: 'Product not found or deleted',
    schema: {
      example: {
        message: 'Product not found.',
        data: null,
        meta: { status: 'error', code: 'PRODUCT_NOT_FOUND', id: 'uuid' },
        ts: '2025-10-11T12:30:45.123Z',
      },
    },
  })
  @ApiBadRequestResponse({
    description: 'Missing tenant ID or invalid request body',
    schema: {
      example: {
        message: 'x-tenant-id is required',
        data: null,
        meta: { status: 'error', code: 'TENANT_ID_MISSING' },
        ts: '2025-10-11T12:30:45.123Z',
      },
    },
  })
  @ApiInternalServerErrorResponse({
    description: 'Unexpected error while updating product status',
    schema: {
      example: {
        message: 'Failed to update product status due to an internal error.',
        data: null,
        meta: {
          status: 'error',
          code: 'INTERNAL_ERROR',
          error: 'MongoDB connection lost',
        },
        ts: '2025-10-11T12:30:45.123Z',
      },
    },
  })
  async changeStatus(
    @Req() req: any,
    @Headers('x-tenant-id') tenantIdentifier: string,
    @Param('id') productIdentifier: string,
    @Body('status') status: string,
  ) {
    if (!tenantIdentifier)
      throw new BadRequestException('x-tenant-id is required');

    const actor = {
      id: req?.user?.sub,
      username: req?.user?.username ?? req?.actor?.username,
    };

    const result = await this.sendSafe<any>('product.changeStatus', {
      tenantId: tenantIdentifier,
      id: productIdentifier,
      status,
      actor,
    });
    return result;
  }

  // ───────────────────────────────
  // PROTECTED: Soft Delete (admin)
  // ───────────────────────────────
  @Roles('admin')
  @Delete(':id')
  @ApiBearerAuth('bearer')
  @ApiOperation({
    summary: 'Soft Delete Product (Admin)',
    description: `
Allows an **admin** to archive (soft delete) a product.  
The product remains in the database but marked as deleted.

### 🧩 Flow
1. Requires **JWT token** and **x-tenant-id** header.  
2. Updates 
deleted
 flag and sets status to 
ARCHIVED
.
3. Clears all cache for consistency.

### ⚠️ Notes
- Deleted products will not appear in listings.
- Action is **irreversible** from the public API.
`,
  })
  @ApiParam({ name: 'id', description: 'Product ID', example: 'uuid' })
  @ApiOkResponse({
    description: 'Product archived successfully',
    schema: {
      example: {
        message: 'Product has been archived successfully.',
        data: { id: 'uuid', deleted: true },
        meta: { status: 'success', code: 'PRODUCT_ARCHIVED' },
        ts: '2025-10-11T12:30:45.123Z',
      },
    },
  })
  @ApiNotFoundResponse({
    description: 'Product not found or deleted',
    schema: {
      example: {
        message: 'Product not found.',
        data: null,
        meta: { status: 'error', code: 'PRODUCT_NOT_FOUND', id: 'uuid' },
        ts: '2025-10-11T12:30:45.123Z',
      },
    },
  })
  @ApiBadRequestResponse({
    description: 'Missing tenant ID or invalid request',
    schema: {
      example: {
        message: 'x-tenant-id is required',
        data: null,
        meta: { status: 'error', code: 'TENANT_ID_MISSING' },
        ts: '2025-10-11T12:30:45.123Z',
      },
    },
  })
  @ApiInternalServerErrorResponse({
    description: 'Unexpected error during product deletion',
    schema: {
      example: {
        message: 'Failed to delete product due to an internal error.',
        data: null,
        meta: {
          status: 'error',
          code: 'INTERNAL_ERROR',
          error: 'MongoDB connection lost',
        },
        ts: '2025-10-11T12:30:45.123Z',
      },
    },
  })
  async softDelete(
    @Req() req: any,
    @Headers('x-tenant-id') tenantIdentifier: string,
    @Param('id') productIdentifier: string,
  ) {
    if (!tenantIdentifier)
      throw new BadRequestException('x-tenant-id is required');

    const actor = {
      id: req?.user?.sub,
      username: req?.user?.username ?? req?.actor?.username,
    };

    const result = await this.sendSafe<any>('product.softDelete', {
      tenantId: tenantIdentifier,
      id: productIdentifier,
      actor,
    });
    return result;
  }
}
```

If you want tenant header shown on only some endpoints, move `@ApiTenantHeader(true)` from class to method level as needed.

## ⚙️ 6) Swagger decorators on Gateway controllers (Auth)
`apps/api-gateway/src/auth-gateway.controller.ts` (🔁 update)
```typescript
import {
  BadRequestException,
  Body,
  Controller,
  Get,
  Headers,
  Inject,
  Post,
  Query,
  Req,
  UseGuards,
} from '@nestjs/common';
import { ClientProxy } from '@nestjs/microservices';
import { firstValueFrom, timeout, catchError, throwError } from 'rxjs';
import { SignupDto } from '../../auth-service/src/dto/signup.dto';
import { LoginDto } from '../../auth-service/src/dto/login.dto';
import { VerifyOtpDto } from '../../auth-service/src/dto/verify-otp.dto';
import { JwtAuthGuard, JwtSessionGuard, Public, Roles } from '@app/auth-lib';
import { LogoutSessionDto } from '../../auth-service/src/dto/logout-session.dto';
import { RefreshDto } from '../../auth-service/src/dto/refresh.dto';
import {
  ApiBadRequestResponse, ApiBearerAuth,
  ApiBody,
  ApiConflictResponse, ApiForbiddenResponse,
  ApiInternalServerErrorResponse, ApiNotFoundResponse,
  ApiOkResponse,
  ApiOperation, ApiQuery, ApiUnauthorizedResponse,
} from '@nestjs/swagger';

@Controller('gateway/auth')
export class AuthGatewayController {
  constructor(
    @Inject('AUTH_SERVICE') private readonly authClient: ClientProxy,
  ) {}

  private async sendSafe<T>(cmd: string, payload: any): Promise<T> {
    try {
      return await firstValueFrom(
        this.authClient.send<T>({ cmd }, payload).pipe(
          timeout(10000),
          catchError((error) => {
            const message =
              error?.message ||
              error?.response?.message ||
              'Auth service error';
            const errors = error?.response?.errors;
            return throwError(
              () => new BadRequestException({ message, errors }),
            );
          }),
        ),
      );
    } catch (unexpected: any) {
      throw new BadRequestException(
        unexpected?.response || {
          message: unexpected?.message || 'Auth service error',
        },
      );
    }
  }

  // ───────────────────────────────
  // Signup
  // ───────────────────────────────
  @Public()
  @Post('signup')
  @ApiOperation({
    summary: 'User Signup (Tenant-Aware Registration)',
    description: `
Registers a new user under the provided **tenant** environment.

### 🧩 Flow
1. Validates **x-tenant-id** (must be provided in header).  
2. Creates a new user with securely hashed password.  
3. Automatically sends a **welcome email** (non-blocking).  
4. Handles duplicate or validation errors gracefully.

### ⚠️ Important Notes
- The **x-tenant-id** header is mandatory to associate the user with the correct tenant.
- Duplicate username/email/mobile entries will be rejected.
- Passwords are securely hashed before storage.
`,
  })
  @ApiBody({
    description: 'User signup details',
    type: SignupDto,
    examples: {
      validExample: {
        summary: 'Example signup request',
        value: {
          name: 'John Doe',
          username: 'johndoe',
          email: 'john@example.com',
          password: 'MySecurePassword@123',
          mobile: '01712345678',
        },
      },
    },
  })
  @ApiOkResponse({
    description: 'Account successfully created under tenant',
    schema: {
      example: {
        message:
          'Your account has been created successfully. You can now log in to your AeroStitch workspace.',
        data: {
          status: 'success',
          code: 'USER_CREATED',
          data: {
            id: 'uuid',
            name: 'John Doe',
            username: 'johndoe',
            email: 'john@example.com',
            role: 'user',
          },
        },
        ts: '2025-10-11T12:30:45.123Z',
      },
    },
  })
  @ApiConflictResponse({
    description: 'Duplicate username/email/mobile detected',
    schema: {
      example: {
        message:
          'Signup failed: Some information already exists in the system. Please use different values.',
        data: {
          status: 'error',
          code: 'DUPLICATE_ENTRY',
          message: 'Duplicate fields: email "john@example.com"',
        },
        ts: '2025-10-11T12:30:45.123Z',
      },
    },
  })
  @ApiBadRequestResponse({
    description: 'Validation failed (e.g., invalid email or weak password)',
    schema: {
      example: {
        message:
          'Signup failed due to invalid or missing information. Please review your inputs.',
        data: {
          status: 'error',
          code: 'VALIDATION_FAILED',
          message: 'Password must be at least 6 characters',
        },
        ts: '2025-10-11T12:30:45.123Z',
      },
    },
  })
  @ApiInternalServerErrorResponse({
    description: 'Unexpected server error during signup',
    schema: {
      example: {
        message: 'Signup failed due to a system error. Please try again later.',
        data: {
          status: 'error',
          code: 'INTERNAL_ERROR',
          error: 'Database connection lost',
        },
        ts: '2025-10-11T12:30:45.123Z',
      },
    },
  })
  async signup(
    @Headers('x-tenant-id') tenantId: string,
    @Body() dto: SignupDto,
    @Req() req: any,
  ) {
    if (!tenantId) throw new BadRequestException('x-tenant-id is required');

    const safeReq = {
      user: req.user,
      headers: {
        'user-agent': req.headers['user-agent'] || 'unknown',
        host:
          req.headers['host'] | req.ip ||
          req.connection?.remoteAddress ||
          '0.0.0.0',
      },
    };

    const result = await this.sendSafe<any>('auth.signup', {
      ...dto,
      tenantId,
      req: safeReq,
    });
    return result;
  }

  // ───────────────────────────────
  // Login (send OTP)
  // ───────────────────────────────
  @Public()
  @Post('login')
  @ApiOperation({
    summary: 'User Login (Initiate OTP-based authentication)',
    description: `
Initiates the **OTP-based login flow** by validating credentials and sending a one-time password to the user’s registered email.

### 🧩 Flow
1. Validate tenant connection using **x-tenant-id** header.  
2. Find user by **username/email/mobile**.  
3. Verify password and account status.  
4. Generate OTP (5-minute validity).  
5. Send OTP via email.

### ⚠️ Important Notes
- This endpoint **does not log the user in immediately** — it sends an OTP for the next verification step.
- Locked or suspended users cannot proceed.
`,
  })
  @ApiBody({
    description: 'User credentials for login',
    type: LoginDto,
    examples: {
      validExample: {
        summary: 'Example login request',
        value: {
          usernameOrEmailOrMobile: 'john.doe@example.com',
          password: 'MySecurePassword@123',
        },
      },
    },
  })
  @ApiOkResponse({
    description: 'OTP successfully sent to registered email',
    schema: {
      example: {
        message:
          'A verification OTP has been sent to your registered email address. Please check your inbox.',
        data: {
          status: 'success',
          code: 'OTP_SENT',
          data: {
            loginId: 'f5b2e8c3-8f4a-4a9c-9eab-8b23d67c2337',
            channel: 'email',
            maskedEmail: 'j***@example.com',
          },
        },
        ts: '2025-10-11T12:30:45.123Z',
      },
    },
  })
  @ApiBadRequestResponse({
    description: 'Invalid tenant or missing header',
    schema: {
      example: {
        message:
          'Login failed: Tenant environment is not initialized. Please retry after selecting the correct workspace.',
        data: {
          status: 'error',
          code: 'TENANT_CONNECTION_MISSING',
          details: { tenantId: 'tenant_12345' },
        },
        ts: '2025-10-11T12:30:45.123Z',
      },
    },
  })
  @ApiUnauthorizedResponse({
    description: 'Invalid credentials, locked account, or wrong password',
    schema: {
      oneOf: [
        {
          example: {
            message:
              'Invalid credentials. Please check your username, email, or mobile number and try again.',
            data: {
              status: 'error',
              code: 'INVALID_CREDENTIALS',
              field: 'usernameOrEmailOrMobile',
            },
            ts: '2025-10-11T12:30:45.123Z',
          },
        },
        {
          example: {
            message:
              'Your account is currently locked. Please check your email for unlock instructions or contact support.',
            data: {
              status: 'error',
              code: 'ACCOUNT_LOCKED',
              email: 'john.doe@example.com',
            },
            ts: '2025-10-11T12:30:45.123Z',
          },
        },
        {
          example: {
            message:
              'Incorrect password. Please try again or reset your password if forgotten.',
            data: {
              status: 'error',
              code: 'INVALID_PASSWORD',
              field: 'password',
            },
            ts: '2025-10-11T12:30:45.123Z',
          },
        },
      ],
    },
  })
  @ApiInternalServerErrorResponse({
    description: 'System or email failure',
    schema: {
      oneOf: [
        {
          example: {
            message:
              'We could not send the OTP to your email at this moment. Please try again later.',
            data: {
              status: 'error',
              code: 'OTP_SEND_FAILED',
              error: 'SMTP connection timeout',
            },
            ts: '2025-10-11T12:30:45.123Z',
          },
        },
        {
          example: {
            message:
              'Login failed due to a system error. Please try again later.',
            data: {
              status: 'error',
              code: 'INTERNAL_ERROR',
              error: 'Database connection lost',
            },
            ts: '2025-10-11T12:30:45.123Z',
          },
        },
      ],
    },
  })
  async login(
    @Headers('x-tenant-id') tenantId: string,
    @Body() dto: LoginDto,
    @Req() req: any,
  ) {
    if (!tenantId) throw new BadRequestException('x-tenant-id is required');
    const safeReq = {
      user: req.user,
      headers: {
        'user-agent': req.headers['user-agent'] || 'unknown',
        host:
          req.headers['host'] | req.ip ||
          req.connection?.remoteAddress ||
          '0.0.0.0',
      },
    };
    const result = await this.sendSafe<any>('auth.login', {
      ...dto,
      tenantId,
      req: safeReq,
    });
    return result;
  }

  // ───────────────────────────────
  // Verify OTP → Tokens
  // ───────────────────────────────
  @Public()
  @Post('login/verify')
  @ApiOperation({
    summary: 'Verify OTP and issue JWT tokens',
    description: `
Verifies the OTP and issues **access and refresh tokens** for session-based authentication.

### 🧩 Flow
1. Validate tenant via **x-tenant-id** header.  
2. Verify the OTP against the stored reference.  
3. Issue **JWT tokens** (access & refresh).  
4. Record session information.  
5. Return tokens and user details.
`,
  })
  @ApiBody({
    description: 'OTP verification payload',
    type: VerifyOtpDto,
    examples: {
      validExample: {
        summary: 'Example request',
        value: {
          loginId: '8bfbec7f-3a2f-4d1f-a8e2-92ef1d2f3b77',
          otp: '123456',
        },
      },
    },
  })
  @ApiOkResponse({
    description: 'OTP verified and tokens issued successfully',
    schema: {
      example: {
        message: 'You have successfully logged in to AeroStitch.',
        data: {
          status: 'success',
          code: 'LOGIN_SUCCESS',
          data: {
            accessToken: 'jwt-access-token',
            refreshToken: 'jwt-refresh-token',
            sessionId: 'uuid',
            user: {
              id: 'uuid',
              username: 'johndoe',
              role: 'user',
            },
          },
        },
        ts: '2025-10-11T12:30:45.123Z',
      },
    },
  })
  @ApiUnauthorizedResponse({
    description: 'OTP invalid, expired, or mismatched',
    schema: {
      oneOf: [
        {
          example: {
            message:
              'Your OTP has expired or is invalid. Please request a new OTP to continue.',
            data: {
              status: 'error',
              code: 'OTP_EXPIRED_OR_INVALID',
              loginId: '8bfbec7f-3a2f-4d1f-a8e2-92ef1d2f3b77',
            },
            ts: '2025-10-11T12:30:45.123Z',
          },
        },
        {
          example: {
            message: 'Incorrect OTP entered. Please check and try again.',
            data: {
              status: 'error',
              code: 'INVALID_OTP',
              field: 'otp',
            },
            ts: '2025-10-11T12:30:45.123Z',
          },
        },
      ],
    },
  })
  @ApiBadRequestResponse({
    description: 'Tenant missing or invalid environment',
    schema: {
      example: {
        message:
          'OTP verification failed: Tenant environment not initialized. Please retry.',
        data: {
          status: 'error',
          code: 'TENANT_CONNECTION_MISSING',
          details: { tenantId: 'tenant_abc' },
        },
        ts: '2025-10-11T12:30:45.123Z',
      },
    },
  })
  @ApiInternalServerErrorResponse({
    description: 'Unexpected system error during OTP verification',
    schema: {
      example: {
        message:
          'Login verification failed due to an unexpected system error. Please try again later.',
        data: {
          status: 'error',
          code: 'INTERNAL_ERROR',
          error: 'Redis connection lost',
        },
        ts: '2025-10-11T12:30:45.123Z',
      },
    },
  })
  async verifyOtp(
    @Headers('x-tenant-id') tenantId: string,
    @Body() dto: VerifyOtpDto,
    @Req() req: any,
  ) {
    if (!tenantId) throw new BadRequestException('x-tenant-id is required');
    const safeReq = {
      user: req.user,
      headers: {
        'user-agent': req.headers['user-agent'] || 'unknown',
        host:
          req.headers['host'] | req.ip ||
          req.connection?.remoteAddress ||
          '0.0.0.0',
      },
    };
    const result = await this.sendSafe<any>('auth.verifyOtp', {
      ...dto,
      tenantId,
      req: safeReq,
    });
    return result;
  }

  // ───────────────────────────────
  // Unlock account
  // ───────────────────────────────
  @Public()
  @Get('unlock')
  @ApiOperation({
    summary: 'Unlock Account (via Email Token)',
    description: `
Unlocks a user account using a token received via email after too many failed login attempts.

### 🧩 Flow
1. User receives an **unlock link** through email after repeated login failures.  
2. The link contains a **token** (e.g., 
https://yourapp.com/api/auth/unlock?token=abc123
).
3. The token is verified in Redis; if valid, the user account is unlocked and can log in again.  
4. The unlock token is **deleted** immediately after successful verification.

### ⚠️ Notes
- The **x-tenant-id** header must always be provided.
- The token expires automatically after a set duration (e.g., 30 minutes).
- If the token is invalid, expired, or reused, an appropriate error response is returned.
`,
  })
  @ApiQuery({
    name: 'token',
    required: true,
    description: 'Unlock token from the email link',
    example: 'df81b3e2-58d4-4a55-9b70-1fbd45a9f02e',
  })
  @ApiOkResponse({
    description: 'Account unlocked successfully',
    schema: {
      example: {
        message:
          'Your account has been unlocked successfully. You may now log in again.',
        data: { userId: 'user_uuid', tenantId: 'tenant_abc' },
        meta: { status: 'success', code: 'ACCOUNT_UNLOCKED' },
        ts: '2025-10-11T12:30:45.123Z',
      },
    },
  })
  @ApiBadRequestResponse({
    description: 'Invalid, expired, or incomplete unlock token',
    schema: {
      oneOf: [
        {
          example: {
            message:
              'The unlock link is invalid or has expired. Please request a new unlock email.',
            data: null,
            meta: { status: 'error', code: 'INVALID_OR_EXPIRED_TOKEN' },
            ts: '2025-10-11T12:30:45.123Z',
          },
        },
        {
          example: {
            message:
              'Unlock request failed due to incomplete token data. Please generate a new unlock link.',
            data: null,
            meta: { status: 'error', code: 'TOKEN_DATA_INCOMPLETE' },
            ts: '2025-10-11T12:30:45.123Z',
          },
        },
      ],
    },
  })
  @ApiInternalServerErrorResponse({
    description: 'Unexpected error during unlock process',
    schema: {
      example: {
        message:
          'Account unlock failed due to a system error. Please try again later.',
        data: null,
        meta: {
          status: 'error',
          code: 'INTERNAL_ERROR',
          error: 'Redis connection lost',
        },
        ts: '2025-10-11T12:30:45.123Z',
      },
    },
  })
  async unlock(
    @Headers('x-tenant-id') tenantId: string,
    @Query('token') token: string,
    @Req() req: any,
  ) {
    if (!tenantId) throw new BadRequestException('x-tenant-id is required');
    const safeReq = {
      user: req.user,
      headers: {
        'user-agent': req.headers['user-agent'] || 'unknown',
        host:
          req.headers['host'] | req.ip ||
          req.connection?.remoteAddress ||
          '0.0.0.0',
      },
    };

    const result = await this.sendSafe<any>('auth.unlock', {
      tenantId,
      token,
      req: safeReq,
    });
    return result;
  }

  // ───────────────────────────────
  // List sessions
  // ───────────────────────────────
  @UseGuards(JwtAuthGuard, JwtSessionGuard)
  @Get('sessions')
  @ApiBearerAuth('bearer')
  @ApiOperation({
    summary: 'List Active User Sessions',
    description: `
Retrieves all **active sessions** for the currently authenticated user.

### 🧩 Flow
1. Requires a valid **JWT access token** (Bearer Auth).  
2. Identifies the user and fetches their **active sessions** from the tenant database.  
3. Returns session metadata such as device, IP, and timestamps.  

### ⚠️ Notes
- The **x-tenant-id** header must always be provided.
- Each session represents a unique login (device/browser).
- Users can have multiple active sessions concurrently.
`,
  })
  @ApiOkResponse({
    description: 'List of active sessions for the authenticated user',
    schema: {
      example: {
        message: 'Active login sessions retrieved successfully.',
        data: [
          {
            sessionId: 'c2a8d1d5-6b91-4c77-a4e0-8b5dfb4dc7a9',
            deviceName: 'Chrome on MacBook',
            ip: '192.168.1.10',
            ua: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)...
            createdAt: '2025-09-18T12:34:56.000Z',
            lastSeen: '2025-09-18T13:00:00.000Z',
          },
          {
            sessionId: 'f87c9e32-3df2-45a4-bb2d-0a1c3c8f3f41',
            deviceName: 'iPhone Safari',
            ip: '172.20.15.23',
            ua: 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)...
            createdAt: '2025-09-19T09:15:22.000Z',
            lastSeen: '2025-09-19T10:02:14.000Z',
          },
        ],
        meta: { status: 'success', code: 'SESSIONS_RETRIEVED' },
        ts: '2025-10-11T12:30:45.123Z',
      },
    },
  })
  @ApiBadRequestResponse({
    description: 'Missing tenant ID or invalid user context',
    schema: {
      oneOf: [
        {
          example: {
            message:
              'Unable to fetch sessions because tenant environment is not initialized.',
            data: null,
            meta: {
              status: 'error',
              code: 'TENANT_CONNECTION_MISSING',
              details: { tenantId: 'tenant_abc' },
            },
            ts: '2025-10-11T12:30:45.123Z',
          },
        },
        {
          example: {
            message:
              'Session request failed: user identity missing in the request payload.',
            data: null,
            meta: { status: 'error', code: 'USER_ID_MISSING' },
            ts: '2025-10-11T12:30:45.123Z',
          },
        },
      ],
    },
  })
  @ApiInternalServerErrorResponse({
    description: 'Unexpected error while fetching user sessions',
    schema: {
      example: {
        message:
          'Failed to retrieve sessions due to a system error. Please try again later.',
        data: null,
        meta: {
          status: 'error',
          code: 'INTERNAL_ERROR',
          error: 'Database connection lost',
        },
        ts: '2025-10-11T12:30:45.123Z',
      },
    },
  })
  async sessions(@Headers('x-tenant-id') tenantId: string, @Req() req: any) {
    if (!tenantId) throw new BadRequestException('x-tenant-id is required');
    const safeReq = {
      user: req.user,
      headers: {
        'user-agent': req.headers['user-agent'] || 'unknown',
        host:
          req.headers['host'] | req.ip ||
          req.connection?.remoteAddress ||
          '0.0.0.0',
      },
    };

    const result = await this.sendSafe<any>('auth.sessions', {
      tenantId,
      req: safeReq,
    });
    return result;
  }

  // ───────────────────────────────
  // Logout single session
  // ───────────────────────────────
  @UseGuards(JwtAuthGuard, JwtSessionGuard)
  @Post('logout/session')
  @ApiBearerAuth('bearer')
  @ApiOperation({
    summary: 'Logout a Single Active Session',
    description: `
Revokes a specific user session identified by its **sessionId**.

### 🧩 Flow
1. Requires a valid **JWT access token** (Bearer Auth).  
2. The **sessionId** (UUID) of the target session must be provided.  
3. The specified session will be removed from the user's active sessions list.  
4. A success response is returned if the session is successfully revoked.

### ⚠️ Notes
- The **x-tenant-id** header must be provided.
- If the session is already logged out or not found, a relevant message is returned.
- This does **not** affect other active sessions.
`,
  })
  @ApiBody({
    description: 'Payload containing the sessionId to revoke',
    type: LogoutSessionDto,
    examples: {
      validExample: {
        summary: 'Example logout request',
        value: { sessionId: 'b9f7f3d3-3a6e-4f34-bc23-8490dfdf1234' },
      },
    },
  })
  @ApiOkResponse({
    description: 'Session revoked successfully',
    schema: {
      example: {
        message: 'Session has been revoked successfully.',
        data: { sessionId: 'b9f7f3d3-3a6e-4f34-bc23-8490dfdf1234' },
        meta: { status: 'success', code: 'SESSION_REVOKED' },
        ts: '2025-10-11T12:30:45.123Z',
      },
    },
  })
  @ApiBadRequestResponse({
    description: 'Missing tenant ID or user identity',
    schema: {
      oneOf: [
        {
          example: {
            message:
              'Logout failed because tenant environment is not initialized.',
            data: null,
            meta: {
              status: 'error',
              code: 'TENANT_CONNECTION_MISSING',
              details: { tenantId: 'tenant_abc' },
            },
            ts: '2025-10-11T12:30:45.123Z',
          },
        },
        {
          example: {
            message: 'Logout request missing user identity.',
            data: null,
            meta: { status: 'error', code: 'USER_ID_MISSING' },
            ts: '2025-10-11T12:30:45.123Z',
          },
        },
      ],
    },
  })
  @ApiNotFoundResponse({
    description: 'Session not found or already logged out',
    schema: {
      example: {
        message: 'Session not found or already logged out.',
        data: null,
        meta: {
          status: 'error',
          code: 'SESSION_NOT_FOUND',
          details: { sessionId: 'b9f7f3d3-3a6e-4f34-bc23-8490dfdf1234' },
        },
        ts: '2025-10-11T12:30:45.123Z',
      },
    },
  })
  @ApiInternalServerErrorResponse({
    description: 'Unexpected error while revoking session',
    schema: {
      example: {
        message: 'Logout failed due to a system error. Please try again later.',
        data: null,
        meta: {
          status: 'error',
          code: 'INTERNAL_ERROR',
          error: 'Database update failed',
        },
        ts: '2025-10-11T12:30:45.123Z',
      },
    },
  })
  async logoutSession(
    @Headers('x-tenant-id') tenantId: string,
    @Req() req: any,
    @Body() dto: LogoutSessionDto,
  ) {
    if (!tenantId) throw new BadRequestException('x-tenant-id is required');
    const safeReq = {
      user: req.user,
      headers: {
        'user-agent': req.headers['user-agent'] || 'unknown',
        host:
          req.headers['host'] | req.ip ||
          req.connection?.remoteAddress ||
          '0.0.0.0',
      },
    };

    const result = await this.sendSafe<any>('auth.logoutSession', {
      tenantId,
      req: safeReq,
      sessionId: dto.sessionId,
    });
    return result;
  }

  // ───────────────────────────────
  // Logout all sessions
  // ───────────────────────────────
  @UseGuards(JwtAuthGuard, JwtSessionGuard)
  @Post('logout/all')
  @ApiBearerAuth('bearer')
  @ApiOperation({
    summary: 'Logout All Active Sessions',
    description: `
Revokes **all active user sessions** for the authenticated user.
`,
  })
  @ApiOkResponse({
    description: 'All sessions revoked successfully',
    schema: {
      example: {
        message: 'All sessions have been revoked successfully.',
        data: { revokedCount: 3 },
        meta: { status: 'success', code: 'ALL_SESSIONS_REVOKED' },
        ts: '2025-10-11T12:30:45.123Z',
      },
    },
  })
  @ApiBadRequestResponse({
    description: 'Missing tenant ID or invalid user context',
    schema: {
      oneOf: [
        {
          example: {
            message:
              'Unable to perform logout-all because tenant environment is not initialized.',
            data: null,
            meta: {
              status: 'error',
              code: 'TENANT_CONNECTION_MISSING',
              details: { tenantId: 'tenant_abc' },
            },
            ts: '2025-10-11T12:30:45.123Z',
          },
        },
        {
          example: {
            message: 'Logout-all request missing user identity.',
            data: null,
            meta: { status: 'error', code: 'USER_ID_MISSING' },
            ts: '2025-10-11T12:30:45.123Z',
          },
        },
      ],
    },
  })
  @ApiInternalServerErrorResponse({
    description: 'Unexpected error during logout-all operation',
    schema: {
      example: {
        message:
          'Logout-all failed due to a system error. Please try again later.',
        data: null,
        meta: {
          status: 'error',
          code: 'INTERNAL_ERROR',
          error: 'Database connection lost',
        },
        ts: '2025-10-11T12:30:45.123Z',
      },
    },
  })
  async logoutAll(@Headers('x-tenant-id') tenantId: string, @Req() req: any) {
    if (!tenantId) throw new BadRequestException('x-tenant-id is required');
    const safeReq = {
      user: req.user,
      headers: {
        'user-agent': req.headers['user-agent'] || 'unknown',
        host:
          req.headers['host'] | req.ip ||
          req.connection?.remoteAddress ||
          '0.0.0.0',
      },
    };

    const result = await this.sendSafe<any>('auth.logoutAll', {
      tenantId,
      req: safeReq,
    });
    return result;
  }

  // ───────────────────────────────
  // Refresh tokens
  // ───────────────────────────────
  @UseGuards(JwtAuthGuard, JwtSessionGuard)
  @Post('refresh')
  @ApiBearerAuth('bearer')
  @ApiOperation({
    summary: 'Refresh Access and Refresh Tokens',
    description: `
Rotates and issues a new **access token** and **refresh token** when the current access token has expired.
`,
  })
  @ApiBody({
    description: 'Payload containing refresh token for rotation',
    type: RefreshDto,
    examples: {
      validExample: {
        summary: 'Example refresh request',
        value: { refreshToken: 'existing-jwt-refresh-token' },
      },
    },
  })
  @ApiOkResponse({
    description: 'Tokens refreshed successfully',
    schema: {
      example: {
        message: 'Access and refresh tokens have been renewed successfully.',
        data: {
          accessToken: 'new-jwt-access-token',
          refreshToken: 'new-jwt-refresh-token',
        },
        meta: { status: 'success', code: 'TOKENS_REFRESHED' },
        ts: '2025-10-11T12:30:45.123Z',
      },
    },
  })
  @ApiUnauthorizedResponse({
    description: 'Invalid or expired refresh token or session mismatch',
    schema: {
      oneOf: [
        {
          example: {
            message:
              'The provided refresh token is invalid or has expired. Please log in again.',
            data: null,
            meta: { status: 'error', code: 'INVALID_REFRESH_TOKEN' },
            ts: '2025-10-11T12:30:45.123Z',
          },
        },
        {
          example: {
            message: 'Session not found or expired. Please log in again.',
            data: null,
            meta: {
              status: 'error',
              code: 'SESSION_NOT_FOUND',
              details: { sessionId: 'uuid' },
            },
            ts: '2025-10-11T12:30:45.123Z',
          },
        },
      ],
    },
  })
  @ApiBadRequestResponse({
    description: 'Missing tenant ID or invalid payload',
    schema: {
      example: {
        message:
          'Token refresh failed because tenant environment is not initialized.',
        data: null,
        meta: {
          status: 'error',
          code: 'TENANT_CONNECTION_MISSING',
          details: { tenantId: 'tenant_abc' },
        },
        ts: '2025-10-11T12:30:45.123Z',
      },
    },
  })
  @ApiInternalServerErrorResponse({
    description: 'Unexpected error while refreshing tokens',
    schema: {
      example: {
        message:
          'Token refresh failed due to a system error. Please try again later.',
        data: null,
        meta: {
          status: 'error',
          code: 'INTERNAL_ERROR',
          error: 'Redis connection lost',
        },
        ts: '2025-10-11T12:30:45.123Z',
      },
    },
  })
  async refresh(
    @Headers('x-tenant-id') tenantId: string,
    @Req() req: any,
    @Body() dto: RefreshDto,
  ) {
    if (!tenantId) throw new BadRequestException('x-tenant-id is required');
    const safeReq = {
      user: req.user,
      headers: {
        'user-agent': req.headers['user-agent'] || 'unknown',
        host:
          req.headers['host'] | req.ip ||
          req.connection?.remoteAddress ||
          '0.0.0.0',
      },
    };

    const result = await this.sendSafe<any>('auth.refresh', {
      tenantId,
      req: safeReq,
      refreshToken: dto.refreshToken,
    });
    return result;
  }

  // ───────────────────────────────
  // Change role
  // ───────────────────────────────
  // @Public() 
  @Roles('admin')
  @Post('change-role')
  @ApiBearerAuth('bearer')
  @ApiOperation({
    summary: 'Change User Role (Admin Only)',
    description: `
Allows an **admin** to update another user's role within the same tenant environment.
`,
  })
  @ApiBody({
    description: 'Payload to update a user’s role',
    schema: {
      type: 'object',
      properties: {
        userId: {
          type: 'string',
          example: 'f9b6de24-1f5d-4b55-b50e-1fab249bb552',
          description: 'User ID to update role for',
        },
        newRole: {
          type: 'string',
          example: 'admin',
          description: 'New role to assign (e.g., user, manager, admin)',
        },
      },
      required: ['userId', 'newRole'],
    },
  })
  @ApiOkResponse({
    description: 'User role updated successfully',
    schema: {
      example: {
        message: 'User role has been updated successfully.',
        data: {
          id: 'uuid',
          username: 'johndoe',
          email: 'john@example.com',
          previousRole: 'user',
          newRole: 'admin',
        },
        meta: { status: 'success', code: 'USER_ROLE_UPDATED' },
        ts: '2025-10-11T12:30:45.123Z',
      },
    },
  })
  @ApiBadRequestResponse({
    description: 'User not found or tenant connection missing',
    schema: {
      oneOf: [
        {
          example: {
            message:
              'Role update failed because tenant environment is not initialized.',
            data: null,
            meta: {
              status: 'error',
              code: 'TENANT_CONNECTION_MISSING',
              details: { tenantId: 'tenant_abc' },
            },
            ts: '2025-10-11T12:30:45.123Z',
          },
        },
        {
          example: {
            message:
              'No user found with the provided identifier. Please verify and try again.',
            data: null,
            meta: {
              status: 'error',
              code: 'USER_NOT_FOUND',
              details: { userId: 'f9b6de24-1f5d-4b55-b50e-1fab249bb552' },
            },
            ts: '2025-10-11T12:30:45.123Z',
          },
        },
      ],
    },
  })
  @ApiForbiddenResponse({
    description: 'User lacks admin privileges',
    schema: {
      example: {
        message: 'Access denied: Admin role required to change user roles.',
        data: null,
        meta: { status: 'error', code: 'FORBIDDEN' },
        ts: '2025-10-11T12:30:45.123Z',
      },
    },
  })
  @ApiInternalServerErrorResponse({
    description: 'Unexpected error during role update',
    schema: {
      example: {
        message:
          'Role update failed due to a system error. Please try again later.',
        data: null,
        meta: {
          status: 'error',
          code: 'INTERNAL_ERROR',
          error: 'Database write conflict',
        },
        ts: '2025-10-11T12:30:45.123Z',
      },
    },
  })
  async changeUserRole(
    @Headers('x-tenant-id') tenantId: string,
    @Body('userId') userId: string,
    @Body('newRole') newRole: string,
    @Req() req: any,
  ) {
    if (!tenantId) throw new BadRequestException('x-tenant-id is required');
    const safeReq = {
      user: req.user,
      headers: {
        'user-agent': req.headers['user-agent'] || 'unknown',
        host:
          req.headers['host'] | req.ip ||
          req.connection?.remoteAddress ||
          '0.0.0.0',
      },
    };

    const result = await this.sendSafe<any>('auth.changeUserRole', {
      tenantId,
      userId,
      newRole,
      req: safeReq,
    });
    return result;
  }

  // ───────────────────────────────
  // Get Current User (from Access Token)
  // ───────────────────────────────
  @UseGuards(JwtAuthGuard)
  @Get('me')
  @ApiBearerAuth('bearer')
  @ApiOperation({
    summary: 'Get Current User Profile',
    description: `
Returns the currently authenticated user's profile information based on the access token.  
This endpoint extracts the JWT access token from the request header and fetches the user's latest details from the database through the Auth microservice.
    `,
  })
  @ApiOkResponse({
    description: 'User retrieved successfully',
    schema: {
      example: {
        message: 'Current user retrieved successfully.',
        data: {
          id: '66a0a2f47b85d048ae5b11d2',
          username: 'john.doe',
          name: 'John Doe',
          email: 'john@example.com',
          mobile: '+8801711111111',
          role: 'admin',
          tenantId: 'aero1',
          sessionId: 'f67a1c5d-59ea-4322-8edb-ff1815b1f38e',
          lastLoginAt: '2025-10-25T15:42:10.125Z',
          createdAt: '2025-01-10T12:30:45.123Z',
          updatedAt: '2025-10-25T15:42:10.125Z',
        },
        meta: {
          status: 'success',
          code: 'CURRENT_USER_OK',
        },
        ts: '2025-10-26T13:05:00.235Z',
      },
    },
  })
  @ApiUnauthorizedResponse({
    description: 'Invalid or expired access token',
    schema: {
      example: {
        message: 'Invalid or expired access token.',
        data: null,
        meta: {
          status: 'error',
          code: 'INVALID_ACCESS_TOKEN',
        },
        ts: '2025-10-26T13:05:00.235Z',
      },
    },
  })
  @ApiBadRequestResponse({
    description: 'Missing tenant ID',
    schema: {
      example: {
        message: 'x-tenant-id is required',
        error: 'Bad Request',
        statusCode: 400,
      },
    },
  })
  @ApiInternalServerErrorResponse({
    description: 'Unexpected error occurred while retrieving current user',
    schema: {
      example: {
        message: 'Failed to retrieve current user.',
        data: null,
        meta: {
          status: 'error',
          code: 'INTERNAL_ERROR',
          error: 'Database connection lost',
        },
        ts: '2025-10-26T13:05:00.235Z',
      },
    },
  })
  async getCurrentUser(
    @Headers('x-tenant-id') tenantId: string,
    @Req() req: any,
  ) {
    if (!tenantId) throw new BadRequestException('x-tenant-id is required');

    const safeReq = {
      user: req.user,
      headers: {
        'user-agent': req.headers['user-agent'] || 'unknown',
        host:
          req.headers['host'] | req.ip ||
          req.connection?.remoteAddress ||
          '0.0.0.0',
      },
    };

    const accessToken =
      req.headers['authorization'] || req.headers['Authorization'];
    if (!accessToken) {
      throw new BadRequestException('Authorization header is required');
    }

    const token = accessToken.replace(/^Bearer\s+/i, '');

    const result = await this.sendSafe<any>('auth.get-current-user', {
      tenantId,
      token,
      req: safeReq,
    });

    return result;
  }
}
```

## ⚙️ 7) (Optional) Swagger on internal services’ HTTP endpoints
You can also annotate auth-service, tenant-service, and product-service HTTP controllers similarly.

For internal services that are usually called through the Gateway, restrict UI to dev only (we already do this in `main.ts`).

## ⚙️ 8) Verify
First of all, <span style="color: red;">stop and run all the services again.</span>

**Gateway docs:** `http://localhost:3501/docs`
*   Try “Products (Gateway)” tag:
    *   Public list/get → no Authorize needed.
    *   Create/update/change-status/delete → click Authorize, paste `Bearer <ACCESS_TOKEN>`.

**Service docs:**
*   Auth: `http://localhost:3502/docs`
*   Tenant: `http://localhost:3503/docs`
*   Product: `http://localhost:3505/docs`

**OpenAPI JSON files should appear in `openapi/`:**
*   `openapi/api-gateway.json`
*   `openapi/auth-service.json`
*   `openapi/tenant-service.json`
*   `openapi/product-service.json`

## Best practices we applied
*   Single shared helper for Swagger config → keeps all apps consistent.
*   Bearer security scheme named "bearer" and applied selectively:
    *   Public endpoints: no `@ApiBearerAuth`.
    *   Protected endpoints: with `@ApiBearerAuth('bearer')`.
*   Tenant awareness: `@ApiTenantHeader()` decorator documents the required `x-tenant-id` header.
*   Examples and descriptions on DTOs, query params, and bodies → better consumer UX.
*   Export OpenAPI on boot → CI/CD can publish spec artifacts (Stoplight, SwaggerHub, etc.).
*   Docs only in non-prod by default → safer exposure policy.

```