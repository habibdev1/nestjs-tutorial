import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';
import { v4 as uuidv4 } from 'uuid';

export type TenantDocument = Tenant & Document;

export enum TenantStatus {
  PENDING = 'PENDING',
  ACTIVE = 'ACTIVE',
  INACTIVE = 'INACTIVE',
  LOCKED = 'LOCKED',
  SUSPENDED = 'SUSPENDED',
}

@Schema({ timestamps: true, versionKey: false })
export class Tenant {
  @Prop({
    type: String,
    default: uuidv4,
  })
  _id: string; // UUID primary key

  @Prop({ required: true, unique: true, trim: true, lowercase: true })
  name: string;

  @Prop({ required: true, trim: true })
  displayName: string;

  @Prop({ required: true, trim: true })
  contactEmail: string;

  @Prop({ type: String, enum: TenantStatus, default: TenantStatus.PENDING })
  status: TenantStatus;

  @Prop({ type: Boolean, default: false })
  deleted: boolean;
}

export const TenantSchema = SchemaFactory.createForClass(Tenant);

TenantSchema.index({ name: 1 }, { unique: true });
TenantSchema.index({ status: 1, deleted: 1 });
