import { Schema } from 'mongoose';

export const SessionSchema = new Schema(
  {
    sessionId: { type: String, required: true },
    deviceName: { type: String },
    ip: { type: String },
    ua: { type: String },
    refreshHash: { type: String },
    createdAt: { type: Date, default: Date.now },
    lastSeen: { type: Date, default: Date.now },
    revokedAt: { type: Date },
  },
  { _id: false },
);

export const UserSchema = new Schema(
  {
    name: { type: String, required: true },
    username: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    mobile: { type: String, required: true },
    password: { type: String, required: true },
    role: { type: String, enum: ['user', 'manager', 'admin'], default: 'user' },
    status: { type: Number, default: 1 }, // 1 = active
    sessions: { type: [SessionSchema], default: [] }, // 👈 for Step 8.3
  },
  { timestamps: true },
);
