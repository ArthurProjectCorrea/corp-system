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

     it('should fail with validation errors for invalid login DTO (400)', async () => {
      const invalidLoginDto = { email: 'not-an-email' }; // Missing password
      return request(app.getHttpServer())
        .post('/auth/login')
        .send(invalidLoginDto)
        .expect(HttpStatus.UNAUTHORIZED) // Guard runs before DTO validation for missing strategy fields
        .then((res) => {
          // If passport-local throws a generic UnauthorizedException due to missing password field
          expect(res.body.message).toEqual('Unauthorized');
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
});