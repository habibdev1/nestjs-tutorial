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
    const tenant = await this.service.findByName(name);
    const data = await this.service.changeStatus(tenant._id, body.status);
    return apiResponse(`Tenant status changed to ${body.status}`, data);
  }

  @Get('by-name/:name/status')
  async getStatusByName(@Param('name') name: string) {
    const tenant = await this.service.findByName(name);
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
  async handleFindAll(
    @Payload()
    payload: {
      status?: TenantStatus;
      page?: number;
      pageSize?: number;
    },
  ) {
    const { data, total, meta } = await this.service.findAll(
      payload.status as TenantStatus,
      payload.page,
      payload.pageSize,
    );
    return apiResponse('Tenant list fetched successfully (TCP)', data, meta);
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
    return apiResponse(
      `Tenant status changed to ${payload.status} (TCP)`,
      data,
    );
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
