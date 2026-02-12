import { Test, TestingModule } from '@nestjs/testing';
import { DatabaseLibService } from './database-lib.service';

describe('DatabaseLibService', () => {
  let service: DatabaseLibService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [DatabaseLibService],
    }).compile();

    service = module.get<DatabaseLibService>(DatabaseLibService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });
});
