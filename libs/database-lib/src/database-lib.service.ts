import {
  Injectable,
  Logger,
  InternalServerErrorException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import mongoose, { Connection, ConnectOptions } from 'mongoose';

/**
 * DatabaseLibService
 * ------------------
 * - Manages per-tenant MongoDB connections.
 * - Each tenant gets a dedicated DB: {MONGO_DB_PREFIX}_{tenantName}.
 * - Connections are cached for reuse.
 */
@Injectable()
export class DatabaseLibService {
  private readonly logger = new Logger(DatabaseLibService.name);
  private readonly connections = new Map<string, Connection>();

  constructor(private readonly config: ConfigService) {}

  /**
   * Get or create a tenant-specific MongoDB connection.
   * @param tenantName Unique tenant identifier (from x-tenant-id header)
   */
  async getTenantConnection(tenantName: string): Promise<Connection> {
    if (!tenantName) {
      throw new InternalServerErrorException(
        'Missing tenantName for DB connection',
      );
    }

    // ✅ Return cached connection if it already exists
    if (this.connections.has(tenantName)) {
      return this.connections.get(tenantName)!;
    }

    // 🔗 Build tenant-specific DB URI
    const baseUri = this.config
      .get<string>('MONGO_URI', 'mongodb://localhost:27017')
      .replace(/\/$/, '');
    const prefix = this.config.get<string>('MONGO_DB_PREFIX', 'aerostitch');
    const dbName = `${prefix}_${tenantName}`;
    const uri = `${baseUri}/${dbName}`;

    const options: ConnectOptions = {
      autoCreate: true,
      retryWrites: true,
      w: 'majority',
    };

    this.logger.log(`🔌 Connecting to tenant DB "${dbName}" at ${uri}`);

    try {
      const conn = await mongoose.createConnection(uri, options).asPromise();
      this.connections.set(tenantName, conn);

      // Observability logs
      conn.on('connected', () =>
        this.logger.log(`✅ Tenant DB connected: ${tenantName}`),
      );
      conn.on('error', (err) =>
        this.logger.error(`❌ Tenant DB error (${tenantName}): ${err.message}`),
      );
      conn.on('disconnected', () =>
        this.logger.warn(`⚠️ Tenant DB disconnected: ${tenantName}`),
      );

      return conn;
    } catch (err) {
      this.logger.error(
        `Failed to connect DB (tenant=${tenantName})`,
        err.stack,
      );
      throw new InternalServerErrorException(
        `Database connection failed for tenant "${tenantName}"`,
      );
    }
  }
}
