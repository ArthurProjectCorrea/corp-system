import { Test, TestingModule } from '@nestjs/testing';
import { HttpStatus, INestApplication, ValidationPipe } from '@nestjs/common';
import * as request from 'supertest';
import { AppModule } from '../src/app.module';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { getRepositoryToken } from '@nestjs/typeorm';
import { User } from '../src/users/user.entity';
import { Repository } from 'typeorm';
import * as bcrypt from 'bcrypt';

describe('UsersController (e2e)', () => {
  let app: INestApplication;
  let userRepository: Repository<User>;
  let originalConfigService: ConfigService;

  // Helper to get values from .env, prioritizing actual env vars
  const getEnvVar = (key: string, defaultValue?: any) => {
    // For tests, we might have actual process.env variables (e.g., in CI)
    // or rely on the .env file loaded by originalConfigService.
    return process.env[key] || originalConfigService?.get(key) || defaultValue;
  };

  beforeAll(async () => {
    // Load the .env file to access TEST_DB_* variables via an initial ConfigService instance
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
            // Map standard DB keys to their TEST_ counterparts
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
                return 'test'; // Ensures synchronize: true for TypeORM
              // Adicionar configurações JWT para consistência e funcionamento correto
              case 'JWT_SECRET':
                return getEnvVar('JWT_SECRET', 'test_users_e2e_secret_key'); // Usar um segredo de teste distinto ou o mesmo do auth
              case 'JWT_EXPIRATION_TIME':
                return getEnvVar('JWT_EXPIRATION_TIME', '30s'); // Expiração curta para testes
              case 'JWT_REFRESH_SECRET':
                return getEnvVar('JWT_REFRESH_SECRET', 'test_users_e2e_refresh_secret_key');
              case 'JWT_REFRESH_EXPIRATION_TIME':
                return getEnvVar('JWT_REFRESH_EXPIRATION_TIME', '60s');
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
    // Clear users table before each test
    await userRepository.clear();
  });

  afterAll(async () => {
    await app.close();
  });

  const defaultUserPassword = 'password123';
  const createUserDto = {
    name: 'Test User',
    email: 'test@example.com',
    password: defaultUserPassword,
  };

  it('/users (POST) - should create a new user', async () => {
    return request(app.getHttpServer())
      .post('/users')
      .send(createUserDto)
      .expect(201)
      .then((res) => {
        expect(res.body).toBeDefined();
        expect(res.body.email).toEqual(createUserDto.email);
        expect(res.body.name).toEqual(createUserDto.name);
        expect(res.body.id).toBeDefined();
        expect(res.body.password).toBeUndefined();
        expect(res.body.createdAt).toBeDefined();
        expect(res.body.updatedAt).toBeDefined();
      });
  });

  it('/users (POST) - should fail to create user with existing email (409)', async () => {
    // Ensure the first user is created and persisted
    const firstUser = await request(app.getHttpServer())
      .post('/users')
      .send(createUserDto)
      .expect(HttpStatus.CREATED);
    expect(firstUser.body.id).toBeDefined();

    // Attempt to create the same user again
    return request(app.getHttpServer())
      .post('/users')
      .send(createUserDto)
      .expect(HttpStatus.CONFLICT)
      .then((res) => {
        expect(res.body.message).toEqual('Email already exists');
      });
  });

  it('/users (POST) - should fail with validation errors for invalid data (400)', async () => {
    const invalidDto = { email: 'not-an-email', name: '' }; // Missing password
    return request(app.getHttpServer())
      .post('/users')
      .send(invalidDto)
      .expect(400)
      .then((res) => {
        expect(res.body.message).toBeInstanceOf(Array);
        expect(res.body.message).toEqual(
          expect.arrayContaining([
            'name should not be empty',
            'email must be an email',
            'password should not be empty',
            'Password must be at least 6 characters long',
          ]),
        );
      });
  });

  describe('with an existing user', () => {
    let existingUser: User;
    let authToken: string;

    beforeEach(async () => {
      // Create user directly via repository to ensure it exists for auth tests
      // This bypasses the API endpoint but ensures the user is in the DB
      const userEntity = userRepository.create({
        ...createUserDto,
        email: 'existing@example.com', // Use a unique email for this block
      });
      // The @BeforeInsert hook should hash the password here
      existingUser = await userRepository.save(userEntity);
      expect(existingUser.id).toBeDefined(); // Ensure ID is present after saving
      // existingUser.password here is the HASHED password.
      // For login, we must use the original plain text defaultUserPassword.
      // We should not use this object directly for assertions that expect SafeUserReturn.

      // Login to get token
      const loginDto = {
        email: 'existing@example.com',
        password: defaultUserPassword,
      };
      const loginRes = await request(app.getHttpServer())
        .post('/auth/login')
        .send(loginDto)
        .expect(HttpStatus.OK);
      authToken = loginRes.body.access_token;
      expect(authToken).toBeDefined();
    });

    it('/users (GET) - should get all users', async () => {
      return request(app.getHttpServer())
        .get('/users')
        .set('Authorization', `Bearer ${authToken}`)
        .expect(HttpStatus.OK)
        .then((res) => {
          expect(Array.isArray(res.body)).toBe(true); // Use Array.isArray for clarity
          expect(res.body.length).toBeGreaterThanOrEqual(1);
          const userInList = res.body.find((u) => u.id === existingUser.id);
          expect(userInList).toBeDefined();
          expect(userInList.email).toEqual(existingUser.email);
          expect(userInList.password).toBeUndefined();
        });
    });

    it('/users/:id (GET) - should get a specific user by id', async () => {
      return request(app.getHttpServer())
        .get(`/users/${existingUser.id}`)
        .set('Authorization', `Bearer ${authToken}`)
        .expect(HttpStatus.OK)
        .then((res) => {
          expect(res.body.id).toEqual(existingUser.id);
          expect(res.body.email).toEqual(existingUser.email);
          expect(res.body.password).toBeUndefined();
        });
    });

    it('/users/:id (PATCH) - should update a user', async () => {
      const updateDto = { name: 'Updated Test User' };
      return request(app.getHttpServer())
        .patch(`/users/${existingUser.id}`)
        .set('Authorization', `Bearer ${authToken}`)
        .send(updateDto)
        .expect(HttpStatus.OK)
        .then((res) => {
          expect(res.body.name).toEqual(updateDto.name);
          expect(res.body.id).toEqual(existingUser.id);
        });
    });

    it('/users/:id (PATCH) - should return 404 for non-existent user', async () => {
      const nonExistentUserId = '00000000-0000-0000-0000-000000000000'; // A non-existent UUID
      const updateDto = { name: 'Updated Test User' };
      return request(app.getHttpServer())
        .patch(`/users/${nonExistentUserId}`)
        .set('Authorization', `Bearer ${authToken}`)
        .send(updateDto)
        .expect(HttpStatus.NOT_FOUND);
    });

    it('/users/:id (DELETE) - should delete a user', async () => {
      await request(app.getHttpServer())
        .delete(`/users/${existingUser.id}`)
        .set('Authorization', `Bearer ${authToken}`)
        .expect(HttpStatus.OK);
      return request(app.getHttpServer()).get(`/users/${existingUser.id}`).set('Authorization', `Bearer ${authToken}`).expect(HttpStatus.NOT_FOUND);
    });

    it('/users/:id (DELETE) - should return 404 for non-existent user', async () => {
      const nonExistentUserId = '00000000-0000-0000-0000-000000000000'; // A non-existent UUID
      return request(app.getHttpServer())
        .delete(`/users/${nonExistentUserId}`)
        .set('Authorization', `Bearer ${authToken}`)
        .expect(HttpStatus.NOT_FOUND);
    });
  });
});