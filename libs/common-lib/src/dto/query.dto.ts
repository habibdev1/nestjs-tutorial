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
