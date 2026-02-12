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
