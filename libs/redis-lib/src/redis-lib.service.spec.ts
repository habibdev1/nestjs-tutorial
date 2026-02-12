import { Test, TestingModule } from '@nestjs/testing';
import { RedisLibService } from './redis-lib.service';

describe('RedisLibService', () => {
  let service: RedisLibService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [RedisLibService],
    }).compile();

    service = module.get<RedisLibService>(RedisLibService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });
});
