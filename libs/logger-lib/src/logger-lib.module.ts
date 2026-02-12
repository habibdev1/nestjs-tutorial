import { Module } from '@nestjs/common';
import { LoggerLibService } from './logger-lib.service';

@Module({
  providers: [LoggerLibService],
  exports: [LoggerLibService],
})
export class LoggerLibModule {}
