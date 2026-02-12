import { Test, TestingModule } from '@nestjs/testing';
import { EmailLibService } from './email-lib.service';

describe('EmailLibService', () => {
  let service: EmailLibService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [EmailLibService],
    }).compile();

    service = module.get<EmailLibService>(EmailLibService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });
});
