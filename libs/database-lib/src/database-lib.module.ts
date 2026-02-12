import { Module } from '@nestjs/common';
import { DatabaseLibService } from './database-lib.service';

@Module({
  providers: [DatabaseLibService],
  exports: [DatabaseLibService],
})
export class DatabaseLibModule {}
