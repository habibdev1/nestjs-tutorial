# ✅ Step 9 — Product CRUD

### Overview
This tutorial, Step 9, is a comprehensive guide that brings together many concepts from our previous tutorials. We will build a complete Product CRUD (Create, Read, Update, Delete) module within our microservice architecture. This step demonstrates how to integrate database management, authentication, Role-Based Access Control (RBAC), and inter-service communication to create a robust and secure feature.

### Microservice Communication
A key focus of this tutorial is the communication between the `api-gateway` and the `product-service`. The flow is as follows:
1.  A client sends an HTTP request to a RESTful endpoint on the `api-gateway`.
2.  The `ProductGatewayController` in the `api-gateway` receives this request.
3.  The gateway controller then dispatches a message to the `product-service` using a reliable and efficient **TCP connection**. This is asynchronous, message-based communication.
4.  The `ProductServiceController` in the `product-service` listens for these incoming TCP messages, processes the request by calling the appropriate service method, and returns the result.
5.  The `api-gateway` receives the response from the `product-service` and forwards it to the original client.

This decoupled architecture ensures that the `product-service` is an independent microservice, handling its own logic and database interactions without being directly exposed to the public.

### Key Implementation Steps
In this tutorial, we will cover the following in detail:
-   **Product Schema:** Define a robust Mongoose schema for our products, including fields for status, garment type, pricing, and auditing.
-   **Data Transfer Objects (DTOs):** Create `CreateProductDto` and `UpdateProductDto` with `class-validator` decorators to ensure all incoming data is well-formed and valid.
-   **Service Layer:** Implement the core business logic for all CRUD operations in the `ProductServiceService`. This includes creating, querying, updating, and deleting products.
-   **Standardized API Responses:** Use a consistent `apiResponse` format for all service methods to ensure predictable and easy-to-handle responses.
-   **Authentication and Authorization:**
    -   Secure the API Gateway endpoints using the `JwtAuthGuard`.
    -   Implement Role-Based Access Control (RBAC) using the `@Roles()` decorator to restrict certain operations (like create, update, and delete) to users with specific roles (e.g., `manager`, `admin`).
-   **Caching with Redis:** Implement caching strategies in the service layer to improve performance for frequently accessed product data.
-   **Multi-Tenancy:** Ensure all database operations are correctly scoped to the tenant ID provided in the request.

## ⚙️ 1) Schema

`apps/product-service/src/schemas/product.schema.ts`

```typescript
import { Schema, Document } from 'mongoose';
import { v4 as uuidv4 } from 'uuid';

export enum ProductStatus {
  DRAFT = 'DRAFT',
  PUBLISHED = 'PUBLISHED',
  ARCHIVED = 'ARCHIVED',
}

export enum GarmentType {
  SHIRT = 'SHIRT',
  PANT = 'PANT',
  JACKET = 'JACKET',
  SUIT = 'SUIT',
  WAISTCOAT = 'WAISTCOAT',
  BLAZER = 'BLAZER',
  OVERCOAT = 'OVERCOAT',
  SKIRT = 'SKIRT',
  DRESS = 'DRESS',
}

// ---- Core interface ----
export interface Product {
  _id: string; // UUID string
  name: string;
  slug: string;
  sku: string;
  garment: GarmentType;
  description: string;
  tags: string[];
  basePrice: number;
  stockQuantity: number;
  images: string[];
  customOptions: { key: string; label: string; value: string }[];
  // Audit
  createdById?: string;
  createdBy?: string;
  updatedById?: string;
  updatedBy?: string;
  // System
  status: ProductStatus;
  deleted: boolean;
  createdAt?: Date;
  updatedAt?: Date;
}

// ---- Document type ----
export type ProductDocument = Product & Document<string>;

// ---- Schema ----
const CustomOptionSchema = new Schema(
  {
    key: { type: String, required: true, trim: true },
    label: { type: String, required: true, trim: true },
    value: { type: String, required: true, trim: true },
  },
  { _id: false },
);

export const ProductSchema = new Schema<ProductDocument>(
  {
    _id: { type: String, default: uuidv4 },
    name: { type: String, required: true, trim: true },
    slug: { type: String, required: true, trim: true },
    sku: { type: String, required: true, trim: true },
    garment: { type: String, enum: Object.values(GarmentType), required: true },
    description: { type: String, default: '' },
    tags: { type: [String], default: [] },
    basePrice: { type: Number, required: true, min: 0 },
    stockQuantity: { type: Number, default: 0 },
    // Audit
    createdById: { type: String },
    createdBy: { type: String },
    updatedById: { type: String },
    updatedBy: { type: String },

    status: {
      type: String,
      enum: Object.values(ProductStatus),
      default: ProductStatus.DRAFT,
    },
    images: { type: [String], default: [] },
    customOptions: { type: [CustomOptionSchema], default: [] },
    deleted: { type: Boolean, default: false },
  },
  { timestamps: true, versionKey: false },
);

// Indexes
ProductSchema.index({ slug: 1 }, { unique: true });
ProductSchema.index({ sku: 1 }, { unique: true });
```

## ⚙️ 2) DTOs

`apps/product-service/src/dto/create-product.dto.ts`

```typescript
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
  @IsString()
  @IsNotEmpty()
  key!: string;

  @IsString()
  @IsNotEmpty()
  label!: string;

  @IsString()
  @IsNotEmpty()
  value!: string;
}

export class CreateProductDto {
  @IsString()
  @IsNotEmpty()
  name!: string;

  @IsString()
  @Matches(/^[a-z0-9-]+$/, {
    message: 'Slug must be lowercase alphanumeric with hyphens',
  })
  slug!: string;

  @IsString()
  @Matches(/^[A-Z0-9-]+$/, {
    message: 'SKU must be uppercase alphanumeric with hyphens',
  })
  sku!: string;

  @IsEnum(GarmentType)
  garment!: GarmentType;

  @IsOptional()
  @IsString()
  description?: string;

  @IsOptional()
  @IsArray()
  tags?: string[];

  @IsNumber()
  @Min(0)
  basePrice!: number;

  @IsOptional()
  @IsNumber()
  stockQuantity?: number;

  @IsOptional()
  @IsEnum(ProductStatus)
  status?: ProductStatus;

  @IsOptional()
  @IsArray()
  images?: string[];

  @IsOptional()
  @ValidateNested({ each: true })
  @Type(() => CustomOptionDto)
  customOptions?: CustomOptionDto[];
}
```

`apps/product-service/src/dto/update-product.dto.ts`

```typescript
import { PartialType } from '@nestjs/mapped-types';
import { CreateProductDto } from './create-product.dto';
export class UpdateProductDto extends PartialType(CreateProductDto) {}
```

`libs/common-lib/src/dto/query.dto.ts`

```typescript
import { IsInt, IsOptional, IsString, Min, IsNumber } from 'class-validator';
import { Transform } from 'class-transformer';

export class ListQueryDto {
  @IsOptional()
  @Transform(({ value }) => Number(value))
  @IsInt()
  @Min(1)
  page?: number = 1;

  @IsOptional()
  @Transform(({ value }) => Number(value))
  @IsInt()
  @Min(1)
  pageSize?: number = 10;

  @IsOptional()
  @IsString()
  q?: string;

  @IsOptional()
  @IsString()
  status?: string; // DRAFT|PUBLISHED|ARCHIVED

  @IsOptional()
  @IsString()
  categoryId?: string;

  @IsOptional()
  @Transform(({ value }) => Number(value))
  @IsNumber()
  minPrice?: number;

  @IsOptional()
  @Transform(({ value }) => Number(value))
  @IsNumber()
  maxPrice?: number;

  @IsOptional()
  @IsString()
  sort?: string; // "createdAt:desc" | "basePrice:asc" | etc.
}
```

Export `ListQueryDto` from `index.ts`

`libs/common-lib/src/index.ts`

```typescript
export * from './common-lib.module';
export * from './common-lib.service';

export * from './response.util';
export * from './dto/query.dto';
```

## ⚙️ 3) Module

`apps/product-service/src/product-service.module.ts`

```typescript
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
```

## ⚙️ 4) Service

We’ll support both:
HTTP: methods receive `httpRequest` and read `httpRequest.tenantConnection` + `httpRequest.tenantId`.

TCP: methods receive `{ tenantId }` and open a connection via a small helper (no global Mongoose).

`apps/product-service/src/product-service.service.ts`

```typescript
import {
  Injectable,
  Logger,
} from '@nestjs/common';
import { Connection, FilterQuery } from 'mongoose';
import { DatabaseLibService } from '@app/database-lib';
import { RedisLibService } from '@app/redis-lib';
import {
  ProductSchema,
  ProductStatus,
  ProductDocument,
} from './schemas/product.schema';
import { CreateProductDto } from './dto/create-product.dto';
import { UpdateProductDto } from './dto/update-product.dto';
import { apiResponse, ListQueryDto } from '@app/common-lib';

@Injectable()
export class ProductServiceService {
  private readonly logger = new Logger(ProductServiceService.name);
  private readonly modelName = 'Product';

  // Cache TTLs (seconds)
  private static readonly LIST_TTL = 120; // lists are frequent; keep fresh
  private static readonly ITEM_TTL = 300; // individual products can live longer

  constructor(
    private readonly databaseLibService: DatabaseLibService,
    private readonly redisLibService: RedisLibService,
  ) {}

  // ── Model factory on an existing tenant connection
  private productModel(tenantConnection: Connection) {
    return tenantConnection.model<ProductDocument>(
      this.modelName,
      ProductSchema,
      'products',
    );
  }

  // ── For TCP paths: open tenant connection by tenantId
  private async productModelByTenantId(tenantIdentifier: string) {
    const tenantConnection =
      await this.databaseLibService.getTenantConnection(tenantIdentifier);
    return this.productModel(tenantConnection);
  }

  // ── Cache key helpers
  private cacheKeyById(tenantIdentifier: string, productId: string) {
    return `product:${tenantIdentifier}:id:${productId}`;
  }
  private cacheKeyBySlug(tenantIdentifier: string, slug: string) {
    return `product:${tenantIdentifier}:slug:${slug}`;
  }
  private cacheKeyForList(
    tenantIdentifier: string,
    listQueryDto: ListQueryDto,
  ) {
    // Normalize dto -> deterministic & compact cache key
    const norm: any = {
      page: Number(listQueryDto.page ?? 1),
      pageSize: Number(listQueryDto.pageSize ?? 10),
    };
    if (listQueryDto.status) norm.status = listQueryDto.status;
    if (listQueryDto.categoryId) norm.categoryId = listQueryDto.categoryId;
    if (listQueryDto.minPrice !== undefined)
      norm.minPrice = Number(listQueryDto.minPrice);
    if (listQueryDto.maxPrice !== undefined)
      norm.maxPrice = Number(listQueryDto.maxPrice);
    if (listQueryDto.q?.trim()) norm.q = listQueryDto.q.trim();
    if (listQueryDto.sort?.trim()) norm.sort = listQueryDto.sort.trim();

    // Avoid overly long keys while preserving uniqueness
    const key = Buffer.from(JSON.stringify(norm)).toString('base64url');
    return `product:${tenantIdentifier}:list:${key}`;
  }

  /** Clear *all* product caches for a tenant (items + lists) */
  private async clearAllProductCaches(tenantIdentifier: string) {
    await this.redisLibService.delPattern(`*product:${tenantIdentifier}:*`);
  }
  

  // ───────────────────────────────
  // TCP — Create Product
  // ───────────────────────────────
  async createTcp(
    tenantIdentifier: string,
    createProductDto: CreateProductDto,
    actor?: { id?: string; username?: string },
  ) {
    try {
      const Product = await this.productModelByTenantId(tenantIdentifier);

      const created = await new Product({
        ...createProductDto,
        createdById: actor?.id,
        createdBy: actor?.username,
        updatedById: actor?.id,
        updatedBy: actor?.username,
      }).save();

      await this.clearAllProductCaches(tenantIdentifier);

      this.logger.log(
        `✅ Product created (tenant=${tenantIdentifier}, sku=${created.sku}, by=${actor?.username})`,
      );

      return apiResponse('Product has been created successfully.', {
        data: created.toObject(),
        meta: { status: 'success', code: 'PRODUCT_CREATED' },
      });
    } catch (err: any) {
      this.logger.error(
        `❌ TCP create product error (tenant=${tenantIdentifier})`,
        err.stack || err,
      );

      if (err?.code === 11000) {
        if (err?.keyValue?.slug)
          return apiResponse('Product slug already exists.', {
            data: null,
            meta: { status: 'error', code: 'DUPLICATE_SLUG' },
          });
        if (err?.keyValue?.sku)
          return apiResponse('Product SKU already exists.', {
            data: null,
            meta: { status: 'error', code: 'DUPLICATE_SKU' },
          });
      }

      return apiResponse('Failed to create product due to an internal error.', {
        data: null,
        meta: {
          status: 'error',
          code: 'INTERNAL_ERROR',
          error: err.message || 'Unknown error',
        },
      });
    }
  }

  // ───────────────────────────────
  // CHECK PRODUCT SKU AVAILABILITY
  // ───────────────────────────────
  async isSkuAvailable(tenantIdentifier: string, sku: string) {
    try {
      const Product = await this.productModelByTenantId(tenantIdentifier);
      const existing = await Product.findOne({ sku }).lean();

      if (existing) {
        this.logger.log(
          `⚠️ SKU already taken (tenant=${tenantIdentifier}, sku=${sku})`,
        );
        return apiResponse('This SKU is already in use.', {
          data: { available: false },
          meta: { status: 'error', code: 'SKU_TAKEN' },
        });
      }

      this.logger.log(
        `✅ SKU available (tenant=${tenantIdentifier}, sku=${sku})`,
      );
      return apiResponse('This SKU is available.', {
        data: { available: true },
        meta: { status: 'success', code: 'SKU_AVAILABLE' },
      });
    } catch (err: any) {
      this.logger.error(
        `❌ Unexpected SKU check error (tenant=${tenantIdentifier})`,
        err.stack || err,
      );
      return apiResponse(
        'SKU check failed due to a system error. Please try again later.',
        {
          data: null,
          meta: {
            status: 'error',
            code: 'INTERNAL_ERROR',
            error: err.message || 'Unknown error',
          },
        },
      );
    }
  }

  // ───────────────────────────────
  // CHECK PRODUCT SLUG AVAILABILITY
  // ───────────────────────────────
  async isSlugAvailable(tenantIdentifier: string, slug: string) {
    try {
      const Product = await this.productModelByTenantId(tenantIdentifier);
      const existing = await Product.findOne({ slug }).lean();

      if (existing) {
        this.logger.log(
          `⚠️ Slug already taken (tenant=${tenantIdentifier}, slug=${slug})`,
        );
        return apiResponse('This product slug is already in use.', {
          data: null,
          meta: { status: 'error', code: 'SLUG_TAKEN' },
        });
      }

      this.logger.log(
        `✅ Slug available (tenant=${tenantIdentifier}, slug=${slug})`,
      );
      return apiResponse('This product slug is available.', {
        data: { available: true },
        meta: { status: 'success', code: 'SLUG_AVAILABLE' },
      });
    } catch (err: any) {
      this.logger.error(
        `❌ Unexpected slug check error (tenant=${tenantIdentifier})`,
        err.stack || err,
      );
      return apiResponse(
        'Slug check failed due to a system error. Please try again later.',
        {
          data: null,
          meta: {
            status: 'error',
            code: 'INTERNAL_ERROR',
            error: err.message || 'Unknown error',
          },
        },
      );
    }
  }

  // ───────────────────────────────
  // TCP — List Products (Public, Paginated)
  // ───────────────────────────────
  async listTcp(tenantIdentifier: string, listQueryDto: ListQueryDto) {
    try {
      const Product = await this.productModelByTenantId(tenantIdentifier);

      const page = Math.max(1, Number(listQueryDto.page ?? 1));
      const pageSize = Math.min(Number(listQueryDto.pageSize ?? 10), 100);
      const skip = (page - 1) * pageSize;

      const filter: Record<string, any> = { deleted: false };
      if (listQueryDto.status) filter.status = listQueryDto.status;
      if (listQueryDto.q?.trim()) {
        const search = listQueryDto.q.trim();
        filter.$or = [
          { name: { $regex: search, $options: 'i' } },
          { sku: { $regex: search, $options: 'i' } },
          { slug: { $regex: search, $options: 'i' } },
        ];
      }

      const total = await Product.countDocuments(filter);
      const data = await Product.find(filter)
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(pageSize)
        .lean()
        .exec();

      const meta = {
        total,
        page,
        pageSize,
        totalPages: Math.max(1, Math.ceil(total / pageSize)),
        status: 'success',
        code: 'PRODUCTS_FETCHED',
      };

      await this.redisLibService.set(
        this.cacheKeyForList(tenantIdentifier, listQueryDto),
        { data, meta },
        ProductServiceService.LIST_TTL,
      );

      this.logger.log(
        `✅ Products listed (tenant=${tenantIdentifier}, total=${total}, page=${page}/${meta.totalPages})`,
      );

      return apiResponse('Products fetched successfully.', {
        data,
        meta,
      });
    } catch (err: any) {
      this.logger.error(
        `❌ TCP list products error (tenant=${tenantIdentifier})`,
        err.stack || err,
      );
      return apiResponse(
        'Failed to fetch product list due to an internal error.',
        {
          data: null,
          meta: {
            status: 'error',
            code: 'INTERNAL_ERROR',
            error: err.message || 'Unknown error',
          },
        },
      );
    }
  }

  // ───────────────────────────────
  // TCP — Get Product by ID
  // ───────────────────────────────
  async getByIdTcp(tenantIdentifier: string, productId: string) {
    try {
      const cacheKey = this.cacheKeyById(tenantIdentifier, productId);
      const cached = await this.redisLibService.get<ProductDocument>(cacheKey);

      if (cached) {
        this.logger.log(
          `⚡ Cache hit for product (tenant=${tenantIdentifier}, id=${productId})`,
        );
        return apiResponse('Product fetched successfully (from cache).', {
          data: cached,
          meta: { status: 'success', code: 'PRODUCT_FETCHED_CACHE' },
        });
      }

      const Product = await this.productModelByTenantId(tenantIdentifier);
      const doc = await Product.findOne({ _id: productId, deleted: false })
        .lean()
        .exec();

      if (!doc) {
        this.logger.warn(
          `⚠️ Product not found (tenant=${tenantIdentifier}, id=${productId})`,
        );
        return apiResponse('Product not found.', {
          data: null,
          meta: { status: 'error', code: 'PRODUCT_NOT_FOUND', id: productId },
        });
      }

      await this.redisLibService.set(
        cacheKey,
        doc,
        ProductServiceService.ITEM_TTL,
      );

      this.logger.log(
        `✅ Product fetched (tenant=${tenantIdentifier}, id=${productId})`,
      );

      return apiResponse('Product fetched successfully.', doc, {
        meta: { status: 'success', code: 'PRODUCT_FETCHED' },
      });
    } catch (err: any) {
      this.logger.error(
        `❌ TCP getById error (tenant=${tenantIdentifier}, id=${productId})`,
        err.stack || err,
      );
      return apiResponse('Failed to fetch product due to an internal error.', {
        data: null,
        meta: {
          status: 'error',
          code: 'INTERNAL_ERROR',
          error: err.message || 'Unknown error',
        },
      });
    }
  }

  // ───────────────────────────────
  // TCP — Get Product by Slug
  // ───────────────────────────────
  async getBySlugTcp(tenantIdentifier: string, slug: string) {
    try {
      const cacheKey = this.cacheKeyBySlug(tenantIdentifier, slug);
      const cached = await this.redisLibService.get<ProductDocument>(cacheKey);

      if (cached) {
        this.logger.log(
          `⚡ Cache hit for product (tenant=${tenantIdentifier}, slug=${slug})`,
        );
        return apiResponse('Product fetched successfully (from cache).', {
          data: cached,
          meta: { status: 'success', code: 'PRODUCT_FETCHED_CACHE' },
        });
      }

      const Product = await this.productModelByTenantId(tenantIdentifier);
      const doc = await Product.findOne({ slug, deleted: false }).lean().exec();

      if (!doc) {
        this.logger.warn(
          `⚠️ Product not found (tenant=${tenantIdentifier}, slug=${slug})`,
        );
        return apiResponse('Product not found.', {
          data: null,
          meta: { status: 'error', code: 'PRODUCT_NOT_FOUND', slug },
        });
      }

      await this.redisLibService.set(
        cacheKey,
        doc,
        ProductServiceService.ITEM_TTL,
      );

      this.logger.log(
        `✅ Product fetched (tenant=${tenantIdentifier}, slug=${slug})`,
      );

      return apiResponse('Product fetched successfully.', doc, {
        meta: { status: 'success', code: 'PRODUCT_FETCHED' },
      });
    } catch (err: any) {
      this.logger.error(
        `❌ TCP getBySlug error (tenant=${tenantIdentifier}, slug=${slug})`,
        err.stack || err,
      );
      return apiResponse('Failed to fetch product due to an internal error.', {
        data: null,
        meta: {
          status: 'error',
          code: 'INTERNAL_ERROR',
          error: err.message || 'Unknown error',
        },
      });
    }
  }

  // ───────────────────────────────
  // TCP — Update Product by ID
  // ───────────────────────────────
  async updateTcp(
    tenantIdentifier: string,
    productId: string,
    updateProductDto: UpdateProductDto,
    actor?: { id?: string; username?: string },
  ) {
    try {
      const Product = await this.productModelByTenantId(tenantIdentifier);
      const updated = await Product.findOneAndUpdate(
        { _id: productId, deleted: false },
        {
          $set: {
            ...updateProductDto,
            updatedById: actor?.id,
            updatedBy: actor?.username,
            updatedAt: new Date(),
          },
        },
        { new: true, runValidators: true, lean: true },
      ).exec();

      if (!updated)
        return apiResponse('Product not found.', {
          data: null,
          meta: { status: 'error', code: 'PRODUCT_NOT_FOUND', id: productId },
        });

      await this.clearAllProductCaches(tenantIdentifier);
      await this.redisLibService.del(
        this.cacheKeyById(tenantIdentifier, productId),
      );

      return apiResponse('Product has been updated successfully.', updated, {
        meta: { status: 'success', code: 'PRODUCT_UPDATED' },
      });
    } catch (err: any) {
      if (err?.code === 11000) {
        if (err?.keyValue?.slug)
          return apiResponse('Product slug already exists.', {
            data: null,
            meta: { status: 'error', code: 'DUPLICATE_SLUG' },
          });
        if (err?.keyValue?.sku)
          return apiResponse('Product SKU already exists.', {
            data: null,
            meta: { status: 'error', code: 'DUPLICATE_SKU' },
          });
      }

      return apiResponse('Failed to update product due to an internal error.', {
        data: null,
        meta: {
          status: 'error',
          code: 'INTERNAL_ERROR',
          error: err.message || 'Unknown error',
        },
      });
    }
  }

  // ───────────────────────────────
  // TCP — Change Product Status
  // ───────────────────────────────
  async changeStatusTcp(
    tenantIdentifier: string,
    productId: string,
    productStatus: ProductStatus,
    actor?: { id?: string; username?: string },
  ) {
    try {
      const Product = await this.productModelByTenantId(tenantIdentifier);
      const updated = await Product.findOneAndUpdate(
        { _id: productId, deleted: false },
        {
          $set: {
            status: productStatus,
            updatedById: actor?.id,
            updatedBy: actor?.username,
            updatedAt: new Date(),
          },
        },
        { new: true, lean: true },
      ).exec();

      if (!updated)
        return apiResponse('Product not found.', {
          data: null,
          meta: { status: 'error', code: 'PRODUCT_NOT_FOUND', id: productId },
        });

      await this.clearAllProductCaches(tenantIdentifier);
      await this.redisLibService.del(
        this.cacheKeyById(tenantIdentifier, productId),
      );

      return apiResponse('Product status has been updated successfully.', {
        data: updated,
        meta: { status: 'success', code: 'PRODUCT_STATUS_UPDATED' },
      });
    } catch (err: any) {
      return apiResponse(
        'Failed to update product status due to an internal error.',
        {
          data: null,
          meta: {
            status: 'error',
            code: 'INTERNAL_ERROR',
            error: err.message || 'Unknown error',
          },
        },
      );
    }
  }

  // ───────────────────────────────
  // TCP — Soft Delete Product
  // ───────────────────────────────
  async softDeleteTcp(
    tenantIdentifier: string,
    productId: string,
    actor?: { id?: string; username?: string },
  ) {
    try {
      const Product = await this.productModelByTenantId(tenantIdentifier);
      const updated = await Product.findOneAndUpdate(
        { _id: productId, deleted: false },
        {
          $set: {
            deleted: true,
            status: ProductStatus.ARCHIVED,
            updatedById: actor?.id,
            updatedBy: actor?.username,
            updatedAt: new Date(),
          },
        },
        { new: true, lean: true },
      ).exec();

      if (!updated)
        return apiResponse('Product not found.', {
          data: null,
          meta: { status: 'error', code: 'PRODUCT_NOT_FOUND', id: productId },
        });

      await this.clearAllProductCaches(tenantIdentifier);
      await this.redisLibService.del(
        this.cacheKeyById(tenantIdentifier, productId),
      );

      return apiResponse('Product has been archived successfully.', {
        data: { id: productId, deleted: true },
        meta: { status: 'success', code: 'PRODUCT_ARCHIVED' },
      });
    } catch (err: any) {
      return apiResponse('Failed to delete product due to an internal error.', {
        data: null,
        meta: {
          status: 'error',
          code: 'INTERNAL_ERROR',
          error: err.message || 'Unknown error',
        },
      });
    }
  }

  // ── shared list pipeline (no tenantId filter since per-tenant DB)
  private async runListQuery(
    Product: any,
    tenantIdentifier: string,
    listQueryDto: ListQueryDto,
  ) {
    const page = Math.min(Number(listQueryDto.page ?? 1), 10_000);
    const pageSize = Math.min(Number(listQueryDto.pageSize ?? 10), 100);

    const filter: FilterQuery<ProductDocument> = { deleted: false };

    if (listQueryDto.status) filter.status = listQueryDto.status as any;
    if (listQueryDto.categoryId)
      (filter as any).categoryId = listQueryDto.categoryId;

    if (
      listQueryDto.minPrice !== undefined ||
      listQueryDto.maxPrice !== undefined
    ) {
      (filter as any).basePrice = {};
      if (listQueryDto.minPrice !== undefined)
        (filter as any).basePrice.$gte = listQueryDto.minPrice;
      if (listQueryDto.maxPrice !== undefined)
        (filter as any).basePrice.$lte = listQueryDto.maxPrice;
    }

    if (listQueryDto.q?.trim()) {
      const queryText = listQueryDto.q.trim();
      filter.$or = [
        { name: { $regex: queryText, $options: 'i' } },
        { description: { $regex: queryText, $options: 'i' } },
        { tags: { $regex: queryText, $options: 'i' } },
        { sku: { $regex: queryText, $options: 'i' } },
      ] as any;
    }

    // Sorting defaults
    let sort: Record<string, 1 | -1> = { createdAt: -1, _id: -1 };
    if (listQueryDto.sort) {
      const [field, dirRaw] = listQueryDto.sort.split(':');
      sort = {
        [field]: dirRaw?.toLowerCase() === 'asc' ? 1 : -1,
        _id: -1,
      };
    }

    const total = await Product.countDocuments(filter);
    const skip = (page - 1) * pageSize;

    const data = await Product.find(filter)
      .sort(sort)
      .skip(skip)
      .limit(pageSize)
      .lean()
      .exec();

    return {
      data,
      meta: {
        total,
        page,
        pageSize,
        totalPages: Math.max(1, Math.ceil(total / pageSize)),
      },
    };
  }
}
```

## ⚙️ 5) Controller (TCP)

`apps/product-service/src/product-service.controller.ts`

```typescript
import { Controller } from '@nestjs/common';
import { MessagePattern, Payload } from '@nestjs/microservices';
import { ProductServiceService } from './product-service.service';
import { CreateProductDto } from './dto/create-product.dto';
import { UpdateProductDto } from './dto/update-product.dto';
import { ListQueryDto } from '@app/common-lib';
import { ProductStatus } from './schemas/product.schema';

@Controller('products')
export class ProductServiceController {
  constructor(private readonly productService: ProductServiceService) {}

  // ───────────────────────────────
  // TCP: Create Product
  // ───────────────────────────────
  @MessagePattern({ cmd: 'product.create' })
  async tcpCreate(
    @Payload()
    payload: {
      tenantId: string;
      dto: CreateProductDto;
      actor?: { id?: string; username?: string };
    },
  ) {
    const result = await this.productService.createTcp(
      payload.tenantId,
      payload.dto,
      payload.actor,
    );
    return result;
  }

  // ───────────────────────────────
  // TCP: Check Product SKU Availability
  // ───────────────────────────────
  @MessagePattern({ cmd: 'product.check-sku' })
  async checkSkuAvailabilityTcp(
    @Payload() payload: { tenantId: string; sku: string },
  ) {
    const result = await this.productService.isSkuAvailable(
      payload.tenantId,
      payload.sku,
    );
    return result;
  }

  // ───────────────────────────────
  // TCP: Check Product Slug Availability
  // ───────────────────────────────
  @MessagePattern({ cmd: 'product.check-slug' })
  async checkSlugAvailabilityTcp(
    @Payload() payload: { tenantId: string; slug: string },
  ) {
    const result = await this.productService.isSlugAvailable(
      payload.tenantId,
      payload.slug,
    );
    return result;
  }

  // ───────────────────────────────
  // TCP: Get Paginated Product List
  // ───────────────────────────────
  @MessagePattern({ cmd: 'product.list' })
  async tcpList(@Payload() payload: { tenantId: string; q: ListQueryDto }) {
    const { data, meta } = await this.productService.listTcp(
      payload.tenantId,
      payload.q,
    );
    return data;
  }

  // ───────────────────────────────
  // TCP: Get Product by ID
  // ───────────────────────────────
  @MessagePattern({ cmd: 'product.getById' })
  async tcpGetById(@Payload() payload: { tenantId: string; id: string }) {
    const result = await this.productService.getByIdTcp(
      payload.tenantId,
      payload.id,
    );
    return result;
  }

  // ───────────────────────────────
  // TCP: Get Product by Slug
  // ───────────────────────────────
  @MessagePattern({ cmd: 'product.getBySlug' })
  async tcpGetBySlug(@Payload() payload: { tenantId: string; slug: string }) {
    const result = await this.productService.getBySlugTcp(
      payload.tenantId,
      payload.slug,
    );
    return result;
  }

  // ───────────────────────────────
  // TCP: Update Product
  // ───────────────────────────────
  @MessagePattern({ cmd: 'product.update' })
  async tcpUpdate(
    @Payload()
    payload: {
      tenantId: string;
      id: string;
      dto: UpdateProductDto;
      actor?: { id?: string; username?: string };
    },
  ) {
    const result = await this.productService.updateTcp(
      payload.tenantId,
      payload.id,
      payload.dto,
      payload.actor,
    );
    return result;
  }

  // ───────────────────────────────
  // TCP: Change Product Status
  // ───────────────────────────────
  @MessagePattern({ cmd: 'product.changeStatus' })
  async tcpChangeStatus(
    @Payload()
    payload: {
      tenantId: string;
      id: string;
      status: ProductStatus;
      actor?: { id?: string; username?: string };
    },
  ) {
    const result = await this.productService.changeStatusTcp(
      payload.tenantId,
      payload.id,
      payload.status,
      payload.actor,
    );
    return result;
  }

  // ───────────────────────────────
  // TCP: Soft Delete Product
  // ───────────────────────────────
  @MessagePattern({ cmd: 'product.softDelete' })
  async tcpSoftDelete(
    @Payload()
    payload: {
      tenantId: string;
      id: string;
      actor?: { id?: string; username?: string };
    },
  ) {
    const result = await this.productService.softDeleteTcp(
      payload.tenantId,
      payload.id,
      payload.actor,
    );
    return result;
  }
}
```

## ⚙️ 6) API Gateway (new product-gateway controller)

`apps/api-gateway/src/product-gateway.controller.ts`

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

Add `PRODUCT_SERVICE` client in `api-gateway.module.ts` (if not already):

```typescript
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
```

Add `ProductGatewayController` to controllers in `api-gateway.module.ts`.

## ⚙️ 7) cURL via Product Gateway

### Create Product (manager/admin)
```bash
curl -X POST http://localhost:3501/gateway/products \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: darmist1" \
  -H "Authorization: Bearer <JWT_TOKEN>" \
  -d '{"name":"Tailored Pant","slug":"tailored-pant","sku":"PANT-101","garment":"PANT","basePrice":2200}' | jq
```

### List Products (public)
```bash
curl "http://localhost:3501/gateway/products?q=pant&sort=createdAt:desc&page=1&pageSize=5" \
  -H "x-tenant-id: darmist1" | jq
```

### Get Product by ID (public)
```bash
curl "http://localhost:3501/gateway/products/PRODUCT_ID" \
  -H "x-tenant-id: darmist1" | jq
```

### Get Product by Slug (public)
```bash
curl "http://localhost:3501/gateway/products/slug/tailored-pant" \
  -H "x-tenant-id: darmist1" | jq
```

### Check SKU Availability (public)
```bash
curl "http://localhost:3501/gateway/products/check-sku/PANT-101" \
  -H "x-tenant-id: darmist1" | jq
```

### Check Slug Availability (public)
```bash
curl "http://localhost:3501/gateway/products/check-slug/tailored-pant" \
  -H "x-tenant-id: darmist1" | jq
```

### Update Product (manager/admin)
```bash
curl -X PATCH http://localhost:3501/gateway/products/PRODUCT_ID \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: darmist1" \
  -H "Authorization: Bearer <JWT_TOKEN>" \
  -d '{"name":"Tailored Pant Updated","basePrice":2500}' | jq
```

### Change Product Status (manager/admin)
```bash
curl -X PATCH http://localhost:3501/gateway/products/PRODUCT_ID/status \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: darmist1" \
  -H "Authorization: Bearer <JWT_TOKEN>" \
  -d '{"status":"inactive"}' | jq
```

### Soft Delete Product (admin only)
```bash
curl -X DELETE http://localhost:3501/gateway/products/PRODUCT_ID \
  -H "x-tenant-id: darmist1" \
  -H "Authorization: Bearer <JWT_TOKEN>" | jq
```