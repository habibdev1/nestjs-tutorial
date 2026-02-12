import { Module } from '@nestjs/common';
import { CommonLibService } from './common-lib.service';

@Module({
  providers: [CommonLibService],
  exports: [CommonLibService],
})
export class CommonLibModule {}
