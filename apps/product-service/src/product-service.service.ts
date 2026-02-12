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
          data: { available: false },
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
