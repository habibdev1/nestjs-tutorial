import { Module } from '@nestjs/common';
import { RedisLibService } from './redis-lib.service';
import { ConfigModule } from '@nestjs/config';

@Module({
  imports: [ConfigModule],
  providers: [RedisLibService],
  exports: [RedisLibService],
})
export class RedisLibModule {}
