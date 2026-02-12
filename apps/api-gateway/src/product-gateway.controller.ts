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
  ApiCreatedResponse,
  ApiForbiddenResponse,
  ApiInternalServerErrorResponse,
  ApiNotFoundResponse,
  ApiOkResponse,
  ApiOperation,
  ApiParam,
  ApiQuery,
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
3. Updates metadata fields (\`updatedBy\`, \`updatedAt\`).  
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
Statuses may include: \`PUBLISHED\`, \`DRAFT\`, or \`ARCHIVED\`.

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
2. Updates \`deleted\` flag and sets status to \`ARCHIVED\`.  
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
