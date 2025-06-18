import { Test, TestingModule } from '@nestjs/testing';
import { HttpStatus, INestApplication, ValidationPipe } from '@nestjs/common';
import * as request from 'supertest';
import { AppModule } from '../src/app.module';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { getRepositoryToken } from '@nestjs/typeorm';
import { User } from '../src/users/user.entity';
import { Repository } from 'typeorm';
import { CreateUserDto } from '../src/users/dto/create-user.dto';

describe('AuthController (e2e)', () => {
  let app: INestApplication;
  let userRepository: Repository<User>;
  let originalConfigService: ConfigService;

  const testUserCredentials = {
    name: 'Auth Test User',
    email: 'auth-test@example.com',
    password: 'password123',
  };

  // Helper to get values from .env, prioritizing actual env vars
  const getEnvVar = (key: string, defaultValue?: any) => {
    return process.env[key] || originalConfigService?.get(key) || defaultValue;
  };

  beforeAll(async () => {
    const configModuleFixture = await Test.createTestingModule({
      imports: [ConfigModule.forRoot({ envFilePath: '.env', ignoreEnvFile: !!process.env.CI })],
    }).compile();
    originalConfigService = configModuleFixture.get<ConfigService>(ConfigService);

    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [AppModule],
    })
    .overrideProvider(ConfigService)
    .useFactory({
      factory: () => ({
        get: (key: string): any => {
          switch (key) {
            case 'DB_HOST':
              return getEnvVar('TEST_DB_HOST', 'localhost');
            case 'DB_PORT':
              return parseInt(getEnvVar('TEST_DB_PORT', '5432'), 10);
            case 'DB_USERNAME':
              return getEnvVar('TEST_DB_USERNAME', 'postgres');
            case 'DB_PASSWORD':
              return getEnvVar('TEST_DB_PASSWORD', 'dev123');
            case 'DB_DATABASE':
              return getEnvVar('TEST_DB_DATABASE', 'database_test');
            case 'NODE_ENV':
              return 'test';
            case 'JWT_SECRET':
              return getEnvVar('JWT_SECRET', 'test_secret_key_e2e'); // Use a consistent test secret
            case 'JWT_EXPIRATION_TIME':
              return getEnvVar('JWT_EXPIRATION_TIME', '60s'); // Short expiration for testing
            case 'JWT_REFRESH_SECRET':
              return getEnvVar('JWT_REFRESH_SECRET', 'test_refresh_secret_key_e2e'); // Consistent test refresh secret
            case 'JWT_REFRESH_EXPIRATION_TIME':
              return getEnvVar('JWT_REFRESH_EXPIRATION_TIME', '120s'); // Short refresh expiration for testing
            case 'PORT':
               return parseInt(getEnvVar('PORT', '3001'), 10);
            default:
              return originalConfigService.get(key) ?? process.env[key];
          }
        },
      }),
    })
    .compile();

    app = moduleFixture.createNestApplication();
    app.useGlobalPipes(
      new ValidationPipe({
        whitelist: true,
        forbidNonWhitelisted: true,
        transform: true,
      }),
    );
    await app.init();

    userRepository = moduleFixture.get<Repository<User>>(getRepositoryToken(User));
  });

  beforeEach(async () => {
    await userRepository.clear();
    // Create user through the API endpoint to ensure all hooks/logic run, including password hashing
    await request(app.getHttpServer())
        .post('/users')
        .send({
        name: testUserCredentials.name,
        email: testUserCredentials.email,
        password: testUserCredentials.password,
        } as CreateUserDto)
        .expect(HttpStatus.CREATED); // Ensure user is created successfully for auth tests
  });


  afterAll(async () => {
    await userRepository.clear(); // Clean up after all tests
    await app.close();
  });

  describe('/auth/login (POST)', () => {
    it('should login an existing user and return a JWT', async () => {
      const loginDto = {
        email: testUserCredentials.email,
        password: testUserCredentials.password,
      };

      return request(app.getHttpServer())
        .post('/auth/login')
        .send(loginDto)
        .expect(HttpStatus.OK) // Login should return 200 OK
        .then((res) => {
          expect(res.body).toBeDefined();
          expect(res.body.access_token).toBeDefined();
          expect(typeof res.body.access_token).toBe('string');
        });
    });

    it('should fail to login with incorrect password (401)', async () => {
      const loginDto = {
        email: testUserCredentials.email,
        password: 'wrongpassword',
      };

      return request(app.getHttpServer())
        .post('/auth/login')
        .send(loginDto)
        .expect(HttpStatus.UNAUTHORIZED)
        .then((res) => {
            expect(res.body.message).toEqual('Credenciais inválidas');
        });
    });

    it('should fail to login with non-existent email (401)', async () => {
      const loginDto = {
        email: 'nonexistent@example.com',
        password: testUserCredentials.password,
      };

      return request(app.getHttpServer())
        .post('/auth/login')
        .send(loginDto)
        .expect(HttpStatus.UNAUTHORIZED)
         .then((res) => {
            expect(res.body.message).toEqual('Credenciais inválidas');
        });
    });

    it('should fail with DTO validation error if password field is missing (400)', async () => {
      // Send a valid email but omit the password field
      const loginDtoMissingPassword = { email: testUserCredentials.email };
      return request(app.getHttpServer())
        .post('/auth/login')
        .send(loginDtoMissingPassword)
        .expect(HttpStatus.BAD_REQUEST) // ValidationPipe now catches missing password
        .then((res) => {
          expect(res.body.message).toBeInstanceOf(Array);
          expect(res.body.message).toEqual(
            expect.arrayContaining(['password should not be empty']),
          );
        });
    });

    it('should fail with DTO validation errors for malformed login data (400)', async () => {
      const malformedLoginDto = {
        email: 'not-an-email-format', // Malformed email
        password: '', // Empty password (violates @IsNotEmpty)
      };
      return request(app.getHttpServer())
        .post('/auth/login')
        .send(malformedLoginDto)
        .expect(HttpStatus.BAD_REQUEST) // ValidationPipe should catch these DTO errors
        .then((res) => {
          expect(res.body.message).toBeInstanceOf(Array);
          expect(res.body.message).toEqual(
            expect.arrayContaining(['email must be an email', 'password should not be empty']),
          );
        });
    });
  });

  describe('/auth/profile (GET)', () => {
    let authToken: string;

    beforeEach(async () => {
      // Login to get a token
      const loginRes = await request(app.getHttpServer())
        .post('/auth/login')
        .send({ email: testUserCredentials.email, password: testUserCredentials.password });
      authToken = loginRes.body.access_token;
    });

    it('should get user profile with a valid JWT', async () => {
      return request(app.getHttpServer())
        .get('/auth/profile')
        .set('Authorization', `Bearer ${authToken}`)
        .expect(HttpStatus.OK)
        .then((res) => {
          expect(res.body).toBeDefined();
          expect(res.body.userId).toBeDefined();
          expect(res.body.email).toEqual(testUserCredentials.email);
          expect(res.body.name).toEqual(testUserCredentials.name);
        });
    });

    it('should fail to get profile without JWT (401)', async () => {
      return request(app.getHttpServer()).get('/auth/profile').expect(HttpStatus.UNAUTHORIZED);
    });

    it('should fail to get profile with an invalid JWT (401)', async () => {
      return request(app.getHttpServer())
        .get('/auth/profile')
        .set('Authorization', 'Bearer invalidtoken123')
        .expect(HttpStatus.UNAUTHORIZED);
    });
  });

  describe('/auth/logout (POST)', () => {
    let authToken: string;

    beforeEach(async () => {
      // Login to get a token
      const loginRes = await request(app.getHttpServer())
        .post('/auth/login')
        .send({ email: testUserCredentials.email, password: testUserCredentials.password })
        .expect(HttpStatus.OK);
      authToken = loginRes.body.access_token;
      expect(authToken).toBeDefined();
    });

    it('should logout a user with a valid JWT and return success message (200)', async () => {
      return request(app.getHttpServer())
        .post('/auth/logout')
        .set('Authorization', `Bearer ${authToken}`)
        .expect(HttpStatus.OK)
        .then((res) => {
          expect(res.body).toBeDefined();
          expect(res.body.message).toEqual('Logout successful. Client should discard the token.');
        });
    });

    it('should fail to logout without JWT (401)', async () => {
      return request(app.getHttpServer()).post('/auth/logout').expect(HttpStatus.UNAUTHORIZED);
    });

    it('should fail to logout with an invalid JWT (401)', async () => {
      return request(app.getHttpServer())
        .post('/auth/logout')
        .set('Authorization', 'Bearer invalidtoken123')
        .expect(HttpStatus.UNAUTHORIZED);
    });
  });

  describe('/auth/refresh (POST)', () => {
    let validRefreshToken: string;

    beforeEach(async () => {
      // Login to get a valid refresh token
      const loginRes = await request(app.getHttpServer())
        .post('/auth/login')
        .send({ email: testUserCredentials.email, password: testUserCredentials.password })
        .expect(HttpStatus.OK);
      validRefreshToken = loginRes.body.refresh_token;
      expect(validRefreshToken).toBeDefined();
    });

    it('should refresh token with a valid refresh_token', async () => {
      return request(app.getHttpServer())
        .post('/auth/refresh')
        .send({ refresh_token: validRefreshToken })
        .expect(HttpStatus.OK)
        .then((res) => {
          expect(res.body.access_token).toBeDefined();
          expect(typeof res.body.access_token).toBe('string');
        });
    });

    it('should fail to refresh with an invalid (malformed) refresh_token (400)', async () => {
      return request(app.getHttpServer())
        .post('/auth/refresh')
        .send({ refresh_token: 'not-a-jwt' })
        .expect(HttpStatus.BAD_REQUEST) // DTO validation should catch this
        .then((res) => {
          expect(res.body.message).toContain('refresh_token must be a jwt string');
        });
    });

    it('should fail to refresh with a non-existent or expired refresh_token (401)', async () => {
      const nonExistentOrExpiredToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJjY2M0YjQyMi1jYjJjLTQxMWEtYTAzNC0yZDE4YjYwZDY5ZjYiLCJpYXQiOjE2NzgwMzY4MDAsImV4cCI6MTY3ODY0MTYwMH0.completelyrandomsignature';
      return request(app.getHttpServer())
        .post('/auth/refresh')
        .send({ refresh_token: nonExistentOrExpiredToken })
        .expect(HttpStatus.UNAUTHORIZED); // AuthService should handle this
    });
  });
});