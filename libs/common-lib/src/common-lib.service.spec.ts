import { Test, TestingModule } from '@nestjs/testing';
import { CommonLibService } from './common-lib.service';

describe('CommonLibService', () => {
  let service: CommonLibService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [CommonLibService],
    }).compile();

    service = module.get<CommonLibService>(CommonLibService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });
});
