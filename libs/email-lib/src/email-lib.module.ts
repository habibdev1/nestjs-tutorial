import { Module } from '@nestjs/common';
import { EmailLibService } from './email-lib.service';
import { ConfigModule } from '@nestjs/config';

@Module({
  imports: [ConfigModule],
  providers: [EmailLibService],
  exports: [EmailLibService],
})
export class EmailLibModule {}
