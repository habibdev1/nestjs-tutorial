import { applyDecorators } from '@nestjs/common';
import { ApiHeader } from '@nestjs/swagger';

/**
 * Adds the tenant header to an endpoint or controller.
 *
 * For Gateway controllers, this is usually required on all endpoints,
 * including PUBLIC ones.
 */
export function ApiTenantHeader(required = true) {
  return applyDecorators(
    ApiHeader({
      name: 'x-tenant-id',
      description: 'Tenant identifier (e.g., "darmist1")',
      required,
      schema: { type: 'string', example: 'darmist1' },
    }),
  );
}
