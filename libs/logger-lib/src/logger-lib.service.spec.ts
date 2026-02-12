import { Test, TestingModule } from '@nestjs/testing';
import { LoggerLibService } from './logger-lib.service';

describe('LoggerLibService', () => {
  let service: LoggerLibService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [LoggerLibService],
    }).compile();

    service = module.get<LoggerLibService>(LoggerLibService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });
});
