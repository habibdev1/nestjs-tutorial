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
