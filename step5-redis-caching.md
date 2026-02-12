# ✅ Step 5 — Redis Caching with Tenant Service

## 🎯 Goal

*   Secure and set up Redis with a dedicated user.
*   Implement RedisLibService using `ioredis` for low-level Redis control.
*   Use RedisLibService in tenant-service to cache tenant lookups (`findById`, `findByName`).
*   Add cache invalidation on updates and deletes.
*   Ensure proper connection lifecycle management with logging.

## ⚙️ 1) Create Redis Account (first-time setup)

If Redis is running locally on port 6379, follow these steps:

```bash
# 1️⃣ Login to Redis
redis-cli -h localhost -p 6379

# 2️⃣ Authenticate as admin (if required)
AUTH your_admin_password

# 3️⃣ Create a dedicated user for Darmist Lab
ACL SETUSER nestjs_tutorial on >'YourSecreetPassword@2025' ~nestjs_tutorial:* +@all

# Explanation:
# - "on" → enable user
# - ">YourSecreetPassword@2025" → set password
# - "~nestjs_tutorial:*" → restrict to keys starting with "nestjs_tutorial:"
# - "+@all" → allow all commands (can be tightened later)

# Save this permanently
SAVE

# Exit redis cli
exit

# 4️⃣ Test login with the new user
redis-cli -h localhost -p 6379 -a 'YourSecreetPassword@2025' --user nestjs_tutorial
```
✅ Now Redis is secured and ready.

## ⚙️ 2) Update Environment Variables

Add in your root `.env`:
```dotenv
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_USER=nestjs_tutorial
REDIS_PASSWORD="YourSecreetPassword@2025"
REDIS_PREFIX=nestjs_tutorial:
```

## ⚙️ 3) Install Dependencies

We’ll use `ioredis`:
```bash
npm install ioredis
```

## ⚙️ 4) Implement RedisLibService

**File:** `libs/redis-lib/src/redis-lib.service.ts`
```typescript
import {Injectable, Logger, OnModuleDestroy, OnModuleInit,} from '@nestjs/common';
import {ConfigService} from '@nestjs/config';
import Redis, {RedisOptions} from 'ioredis';

@Injectable()
export class RedisLibService implements OnModuleInit, OnModuleDestroy {
    private client: Redis;
    private readonly logger = new Logger(RedisLibService.name);

    constructor(private readonly cfg: ConfigService) {
    }

    onModuleInit() {
        const options: RedisOptions = {
            host: this.cfg.get<string>('REDIS_HOST', 'localhost'),
            port: this.cfg.get<number>('REDIS_PORT', 6379),
            username: this.cfg.get<string>('REDIS_USER'),
            password: this.cfg.get<string>('REDIS_PASSWORD'),
            keyPrefix: this.cfg.get<string>('REDIS_PREFIX', 'nestjs_tutorial:'),
        };

        this.client = new Redis(options);

        this.client.on('connect',
            () =>
            this.logger.log('✅ Connected to Redis server'),
        );
        this.client.on('error', (err) =>
            this.logger.error(`❌ Redis error: ${err.message}`, err.stack),
        );
        this.client.on('close',
            () =>
            this.logger.warn('⚠️ Redis connection closed'),
        );
    }

    async onModuleDestroy() {
        await this.client.quit();
        this.logger.log('🔌 Redis connection closed gracefully');
    }

    // ───────────────────────────────
    // OTP helpers
    // ───────────────────────────────

    generateOtp(): string {
        return Math.floor(100000 + Math.random() * 900000).toString();
    }

    async cacheOtp(key: string, code: string, ttl: number): Promise<void> {
        await this.set(key, code, ttl);
    }

    async consumeOtp(key: string, code: string): Promise<boolean> {
        const stored = await this.get<string>(key);
        if (stored !== code) return false;
        await this.del(key);
        return true;
    }

    // ───────────────────────────────
    // Rate limiting helpers
    // ───────────────────────────────

    async exists(key: string): Promise<boolean> {
        return (await this.client.exists(key)) === 1;
    }

    async incr(key: string): Promise<number> {
        return this.client.incr(key);
    }

    async expire(key: string, secs: number): Promise<number> {
        return this.client.expire(key, secs);
    }

    // ───────────────────────────────
    // Generic cache helpers
    // ───────────────────────────────

    async set<T>(key: string, value: T, ttlSeconds = 300): Promise<'OK' | null> {
        const payload = typeof value === 'string' ? value : JSON.stringify(value);
        return this.client.set(key, payload, 'EX', ttlSeconds);
    }

    async get<T>(key: string): Promise<T | null> {
        const val = await this.client.get(key);
        if (!val) return null;
        try {
            return JSON.parse(val) as T;
        } catch {
            return val as unknown as T;
        }
    }

    /**
     * Delete one or multiple keys
     */
    async del(...keys: string[]): Promise<number> {
        if (!keys?.length) return 0;

        const keyPrefix = this.client.options?.keyPrefix ?? '';

        // Reject accidental glob usage here — patterns should go through delPattern()
        const concreteKeys = keys.filter(k => k && !/[*?[\]]/.test(k));
        if (!concreteKeys.length) return 0;

        // If client has keyPrefix, strip it from any incoming fully-qualified keys
        const normalized = keyPrefix
            ? concreteKeys.map(k => (k.startsWith(keyPrefix) ? k.slice(keyPrefix.length) : k))
            : concreteKeys;

        // ioredis DEL supports multiple keys in one call
        return await this.client.del(...normalized);
    }

    /**
     * Delete multiple keys by pattern
     * Uses Redis SCAN to safely iterate without blocking
     */
    async delPattern(pattern: string): Promise<number> {
        const keyPrefix: string = this.client.options?.keyPrefix ?? '';
        const rawInput = (pattern ?? '').trim();

        // Normalize: ensure at least a trailing wildcard if no wildcard provided
        const ensureWildcard = (p: string) => (/[*\\\[\?]/.test(p) ? p : `${p}*`);

        // If caller didn't include the keyPrefix, inject it AFTER any leading '*'s
        const injectPrefixIfMissing = (p: string): string => {
            if (!keyPrefix) return p;

            // Count leading '*' to keep glob behavior intact
            const leadingStarsMatch = p.match(/^\*+/);
            const leadingStars = leadingStarsMatch ? leadingStarsMatch[0] : '';
            const rest = p.slice(leadingStars.length);

            // Already has prefix?
            if (rest.startsWith(keyPrefix)) return p;

            return `${leadingStars}${keyPrefix}${rest}`;
        };

        // 1) sanitize input
        let finalPattern = ensureWildcard(rawInput);
        // 2) inject prefix if missing
        finalPattern = injectPrefixIfMissing(finalPattern);

        // // Debug header
        // this.logger.debug(
        //     [
        //       '🔎 Redis DEL(pattern) debug:',
        //       `• keyPrefix         = "${keyPrefix}"`, 
        //       `• input pattern     = "${rawInput}"`, 
        //       `• normalized MATCH  = "${finalPattern}"`, 
        //     ].join('\n'),
        // );

        let cursor = '0';
        let totalDeleted = 0;
        let scanRounds = 0;
        let totalMatchedKeys = 0;

        try {
            do {
                // Note: SCAN MATCH is evaluated on the *actual* stored keys (with prefix already in DB)
                const [newCursor, keys] = await this.client.scan(
                    cursor,
                    'MATCH',
                    finalPattern,
                    'COUNT',
                    500,
                );

                scanRounds++;
                cursor = newCursor;

                const matchedCount = keys?.length ?? 0;
                totalMatchedKeys += matchedCount;

                // Show a small sample to confirm prefix & shape
                const sample = matchedCount ? keys.slice(0, Math.min(5, matchedCount)) : [];
                this.logger.debug(
                    `• round #${scanRounds}: cursor="${cursor}", matched=${matchedCount}, sample=${JSON.stringify(
                        sample,
                    )}`,
                );

                if (matchedCount > 0) {
                    // IMPORTANT: ioredis will automatically prepend keyPrefix to keys passed to DEL.
                    const keysToDelete = keyPrefix
                        ? keys.map((k) => (k.startsWith(keyPrefix) ? k.slice(keyPrefix.length) : k))
                        : keys;

                    // Optional: log a sample of post-stripped keys
                    const delSample = keysToDelete.slice(0, Math.min(5, keysToDelete.length));
                    this.logger.debug(
                        `• deleting=${keysToDelete.length}, first few (after strip)=${JSON.stringify(
                            delSample,
                        )}`,
                    );

                    // Use DEL (or UNLINK if you prefer non-blocking deletion)
                    const deleted = await this.client.del(...keysToDelete);
                    totalDeleted += deleted;

                    this.logger.debug(`• deleted in this round: ${deleted}`);
                }
            } while (cursor !== '0');

            // this.logger.log(
            //     [
            //       '🧹 Redis DEL(pattern) summary:',
            //       `• MATCH used        = "${finalPattern}"`, 
            //       `• scan rounds       = ${scanRounds}`, 
            //       `• total matched     = ${totalMatchedKeys}`, 
            //       `• total deleted     = ${totalDeleted}`, 
            //     ].join('\n'),
            // );

            return totalDeleted;
        } catch (err) {
            this.logger.error(
                `❌ Redis DEL pattern failed for MATCH="${finalPattern}"`,
                err?.stack ?? String(err),
            );
            return 0;
        }
    }

    async resetAll(): Promise<void> {
        await this.client.flushall();
        this.logger.warn('⚠️ Redis FLUSHALL executed');
    }
}
```

## ⚙️ 5) Redis Module Setup

**File:** `libs/redis-lib/src/redis-lib.module.ts`
```typescript
import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { RedisLibService } from './redis-lib.service';

@Module({
  imports: [ConfigModule],
  providers: [RedisLibService],
  exports: [RedisLibService],
})
export class RedisLibModule {}
```

## ⚙️ 6) Export Redis from Lib

**File:** `libs/redis-lib/src/index.ts`
```typescript
export * from './redis-lib.service';
export * from './redis-lib.module';
```

## ⚙️ 7) Integrate Redis in Tenant Service

Update `apps/tenant-service/src/tenant-service.module.ts`:
```typescript
import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { MongooseModule } from '@nestjs/mongoose';
import { TenantServiceController } from './tenant-service.controller';
import { TenantServiceService } from './tenant-service.service';
import { Tenant, TenantSchema } from './schemas/tenant.schema';
import { RedisLibModule } from '@app/redis-lib';

@Module({
  imports: [
    ConfigModule.forRoot({ isGlobal: true }),

    // DB connection
    MongooseModule.forRootAsync({
      useFactory: (cfg: ConfigService) => ({
        uri: cfg.get<string>('MONGO_URI_TENANT'),
      }),
      inject: [ConfigService],
    }),

    // Register Tenant schema
    MongooseModule.forFeature([{ name: Tenant.name, schema: TenantSchema }]),

    // Redis Caching
    RedisLibModule,
  ],
  controllers: [TenantServiceController],
  providers: [TenantServiceService],
})
export class TenantServiceModule {}
```

## ⚙️ 8) Add Caching to TenantService

Update `apps/tenant-service/src/tenant-service.service.ts`:
```typescript
import {
  Injectable,
  NotFoundException,
  ConflictException,
  Logger,
} from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model, FilterQuery } from 'mongoose';
import { Tenant, TenantDocument, TenantStatus } from './schemas/tenant.schema';
import { CreateTenantDto } from './dto/create-tenant.dto';
import { UpdateTenantDto } from './dto/update-tenant.dto';
import { RedisLibService } from '@app/redis-lib';

@Injectable()
export class TenantServiceService {
  private readonly logger = new Logger(TenantServiceService.name);

  constructor(
    @InjectModel(Tenant.name)
    private readonly tenantModel: Model<TenantDocument>,
    private readonly cache: RedisLibService,
  ) {}

  private cacheKey(idOrName: string) {
    return `tenant:${idOrName}`;
  }

  async create(dto: CreateTenantDto): Promise<Tenant> {
    try {
      const tenant = new this.tenantModel(dto);
      const saved = await tenant.save();

      await this.cache.set(this.cacheKey(saved._id), saved);
      await this.cache.set(this.cacheKey(saved.name), saved);

      return saved;
    } catch (e: any) {
      if (e?.code === 11000)
        throw new ConflictException('Tenant name already exists');
      throw e;
    }
  }

  async findAll(
    status?: TenantStatus,
    page = 1,
    pageSize = 10,
  ): Promise<{ data: Tenant[]; total: number; meta: any }> {
    const query: FilterQuery<Tenant> = { deleted: false };
    if (status) query.status = status;

    const total = await this.tenantModel.countDocuments(query);

    if (page < 0) {
      const data = await this.tenantModel.find(query).lean().exec();
      return {
        data,
        total,
        meta: { total, page: -1, pageSize: total, totalPages: 1 },
      };
    }

    const skip = (page - 1) * pageSize;
    const data = await this.tenantModel
      .find(query)
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(pageSize)
      .lean()
      .exec();

    return {
      data,
      total,
      meta: {
        total,
        page,
        pageSize,
        totalPages: Math.ceil(total / pageSize) || 1,
      },
    };
  }

  async findById(id: string): Promise<Tenant> {
    const key = this.cacheKey(id);
    const cached = await this.cache.get<Tenant>(key);
    if (cached) return cached;

    const doc = await this.tenantModel
      .findOne({ _id: id, deleted: false })
      .lean()
      .exec();
    if (!doc) throw new NotFoundException('Tenant not found');

    await this.cache.set(key, doc, 300);
    return doc;
  }

  async findByName(name: string): Promise<Tenant> {
    const key = this.cacheKey(name);
    const cached = await this.cache.get<Tenant>(key);
    if (cached) {
      this.logger.log('Cache found for ' + key);
      return cached;
    }

    const doc = await this.tenantModel
      .findOne({ name, deleted: false })
      .lean()
      .exec();
    if (!doc) throw new NotFoundException('Tenant not found');

    await this.cache.set(key, doc, 300);
    this.logger.log('Cache set for ' + key);
    return doc;
  }

  async update(id: string, dto: UpdateTenantDto): Promise<Tenant> {
    const updated = await this.tenantModel
      .findOneAndUpdate(
        { _id: id, deleted: false },
        { $set: dto },
        { new: true },
      )
      .lean()
      .exec();
    if (!updated) throw new NotFoundException('Tenant not found');

    await this.cache.set(this.cacheKey(id), updated);
    await this.cache.set(this.cacheKey(updated.name), updated);

    return updated;
  }

  async changeStatus(id: string, status: TenantStatus): Promise<Tenant> {
    const updated = await this.tenantModel
      .findOneAndUpdate(
        { _id: id, deleted: false },
        { $set: { status } },
        { new: true },
      )
      .lean()
      .exec();
    if (!updated) throw new NotFoundException('Tenant not found');

    await this.cache.set(this.cacheKey(id), updated);
    await this.cache.set(this.cacheKey(updated.name), updated);

    return updated;
  }

  async softDelete(id: string): Promise<{ deleted: boolean }> {
    const res = await this.tenantModel
      .findOneAndUpdate(
        { _id: id, deleted: false },
        { $set: { deleted: true, status: TenantStatus.INACTIVE } },
      )
      .lean()
      .exec();
    if (!res) throw new NotFoundException('Tenant not found');

    await this.cache.del(this.cacheKey(id));
    await this.cache.del(this.cacheKey(res.name));

    return { deleted: true };
  }
}
```

## ⚙️ 9) Verify Caching

Start Redis server:
```bash
redis-server
```
Start tenant-service:
```bash
npx nest start tenant-service --watch
```
Create tenant:
```bash
curl -s POST http://localhost:3501/gateway/tenants \
  -H 'Content-Type: application/json' \
  -d '{"name":"darmist1","displayName":"Darmist Lab Sweden","contactEmail":"ops@darmist.com"}'
```
Fetch twice:
```bash
curl -s http://localhost:3501/gateway/tenants/by-name/darmist1
```
First, you will find this message in console log →
```
[Nest] 10478  - 11/05/2025, 5:46:05 PM     LOG [TenantServiceService] Cache set for tenant:darmist1
```
Second time hit, you will see this log →
```
[Nest] 10478  - 11/05/2025, 5:46:19 PM     LOG [TenantServiceService] Cache found for tenant:darmist1
```
Check Redis keys:
```bash
redis-cli -a 'YourSecreetPassword@2025' --user nestjs_tutorial KEYS 'nestjs_tutorial:tenant:darmist1*'
```