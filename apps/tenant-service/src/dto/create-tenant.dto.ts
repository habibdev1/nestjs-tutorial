import {
  IsEmail,
  IsEnum,
  IsOptional,
  IsString,
  Matches,
  MinLength,
} from 'class-validator';
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
