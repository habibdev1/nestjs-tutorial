import { IsEnum } from 'class-validator';
import { TenantStatus } from '../schemas/tenant.schema';

export class ChangeStatusDto {
  @IsEnum(TenantStatus)
  status: TenantStatus;
}
