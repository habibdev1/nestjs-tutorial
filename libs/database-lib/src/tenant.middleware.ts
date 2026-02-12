import {
  Injectable,
  NestMiddleware,
  BadRequestException,
  ForbiddenException,
  Inject,
  Logger,
} from '@nestjs/common';
import { Request, Response, NextFunction } from 'express';
import { DatabaseLibService } from '@app/database-lib';
import { ClientProxy } from '@nestjs/microservices';
import { lastValueFrom, TimeoutError } from 'rxjs';
import { RedisLibService } from '@app/redis-lib';

/**
 * TenantMiddleware
 * ----------------
 * - Extracts tenant name from request header.
 * - Validates tenant via tenant-service (TCP).
 * - Caches tenant validation in Redis.
 * - Ensures tenant is ACTIVE before proceeding.
 * - Attaches tenantConnection to request object.
 */
@Injectable()
export class TenantMiddleware implements NestMiddleware {
  private readonly logger = new Logger(TenantMiddleware.name);

  constructor(
    private readonly dbService: DatabaseLibService,
    @Inject('TENANT_SERVICE') private readonly tenantClient: ClientProxy,
    private readonly cache: RedisLibService,
  ) {}

  async use(req: Request, _res: Response, next: NextFunction) {
    const tenantName = (req.headers['x-tenant-id'] as string)?.trim();
    if (!tenantName) {
      throw new BadRequestException(`Missing 'x-tenant-id' header`);
    }

    // 1️⃣ Try Redis cache first
    let tenantRecord: any = await this.cache.get(`tenant:${tenantName}`);

    // 2️⃣ Fallback to tenant-service (TCP)
    if (!tenantRecord) {
      try {
        await this.tenantClient.connect();
        tenantRecord = await lastValueFrom(
          this.tenantClient.send({ cmd: 'tenant.findByName' }, tenantName),
        );
        if (tenantRecord?.data) {
          tenantRecord = tenantRecord.data;
          await this.cache.set(`tenant:${tenantName}`, tenantRecord, 300);
        }
      } catch (err) {
        if (err instanceof TimeoutError) {
          throw new BadRequestException(`Tenant validation timed out`);
        }
        throw new BadRequestException(`Tenant "${tenantName}" not found`);
      }
    }

    if (!tenantRecord) {
      throw new BadRequestException(`Tenant "${tenantName}" not found`);
    }

    // 3️⃣ Enforce ACTIVE tenants only
    if (tenantRecord.status !== 'ACTIVE') {
      throw new ForbiddenException(`Tenant "${tenantName}" is not active`);
    }

    // 4️⃣ Attach tenant-specific DB connection
    const connection = await this.dbService.getTenantConnection(tenantName);
    (req as any).tenantConnection = connection;

    this.logger.debug(`➡️ TenantMiddleware passed (${tenantName})`);
    next();
  }
}
