import { SetMetadata } from '@nestjs/common';
export type AppRole = 'user' | 'manager' | 'admin';
export const ROLES_KEY = 'app_roles_required';
export const Roles = (...roles: AppRole[]) => SetMetadata(ROLES_KEY, roles);
