import { JwtAuthGuard } from './jwt-auth.guard';
import { Test, TestingModule } from '@nestjs/testing';

describe('JwtAuthGuard', () => {
  let guard: JwtAuthGuard;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [JwtAuthGuard], // PassportModule e JwtStrategy seriam necessários para um teste mais profundo
    }).compile();
    guard = module.get<JwtAuthGuard>(JwtAuthGuard);
  });
  it('should be defined', () => {
    expect(guard).toBeDefined();
  });
});