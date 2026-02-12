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
