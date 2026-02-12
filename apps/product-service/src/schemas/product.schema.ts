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
