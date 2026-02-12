import {
  Injectable,
  Logger,
  OnModuleDestroy,
  OnModuleInit,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import Redis, { RedisOptions } from 'ioredis';

@Injectable()
export class RedisLibService implements OnModuleInit, OnModuleDestroy {
  private client: Redis;
  private readonly logger = new Logger(RedisLibService.name);

  constructor(private readonly cfg: ConfigService) {}

  onModuleInit() {
    const options: RedisOptions = {
      host: this.cfg.get<string>('REDIS_HOST', 'localhost'),
      port: this.cfg.get<number>('REDIS_PORT', 6379),
      username: this.cfg.get<string>('REDIS_USER'),
      password: this.cfg.get<string>('REDIS_PASSWORD'),
      keyPrefix: this.cfg.get<string>('REDIS_PREFIX', 'nestjs_tutorial:'),
    };

    this.client = new Redis(options);

    this.client.on('connect', () =>
      this.logger.log('✅ Connected to Redis server'),
    );
    this.client.on('error', (err) =>
      this.logger.error(`❌ Redis error: ${err.message}`, err.stack),
    );
    this.client.on('close', () =>
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
    const concreteKeys = keys.filter((k) => k && !/[*?\[\]]/.test(k));
    if (!concreteKeys.length) return 0;

    // If client has keyPrefix, strip it from any incoming fully-qualified keys
    const normalized = keyPrefix
      ? concreteKeys.map((k) =>
          k.startsWith(keyPrefix) ? k.slice(keyPrefix.length) : k,
        )
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
    const ensureWildcard = (p: string) => (/[*\[\?]/.test(p) ? p : `${p}*`);

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
        const sample = matchedCount
          ? keys.slice(0, Math.min(5, matchedCount))
          : [];
        this.logger.debug(
          `• round #${scanRounds}: cursor="${cursor}", matched=${matchedCount}, sample=${JSON.stringify(
            sample,
          )}`,
        );

        if (matchedCount > 0) {
          // IMPORTANT: ioredis will automatically prepend keyPrefix to keys passed to DEL.
          const keysToDelete = keyPrefix
            ? keys.map((k) =>
                k.startsWith(keyPrefix) ? k.slice(keyPrefix.length) : k,
              )
            : keys;

          // Optional: log a sample of post-stripped keys
          const delSample = keysToDelete.slice(
            0,
            Math.min(5, keysToDelete.length),
          );
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
