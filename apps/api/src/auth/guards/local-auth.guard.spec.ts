import { LocalAuthGuard } from './local-auth.guard';
import { Test, TestingModule } from '@nestjs/testing';

describe('LocalAuthGuard', () => {
  let guard: LocalAuthGuard;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [LocalAuthGuard], // PassportModule e LocalStrategy seriam necessários para um teste mais profundo
    }).compile();
    guard = module.get<LocalAuthGuard>(LocalAuthGuard);
  });
  it('should be defined', () => {
    expect(guard).toBeDefined();
  });
});