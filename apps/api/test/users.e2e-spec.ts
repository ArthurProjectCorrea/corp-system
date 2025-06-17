import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
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
    await request(app.getHttpServer()).post('/users').send(createUserDto).expect(201);
    return request(app.getHttpServer())
      .post('/users')
      .send(createUserDto)
      .expect(409)
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

    beforeEach(async () => {
      const res = await request(app.getHttpServer())
        .post('/users')
        .send({ ...createUserDto, email: 'existing@example.com' }) // Use a unique email for this block
        .expect(201); // Ensure user creation was successful
      expect(res.body.id).toBeDefined(); // Ensure ID is present
      existingUser = res.body;
    });

    it('/users (GET) - should get all users', async () => {
      return request(app.getHttpServer())
        .get('/users')
        .expect(200)
        .then((res) => {
          expect(res.body).toBeInstanceOf(Array);
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
        .expect(200)
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
        .send(updateDto)
        .expect(200)
        .then((res) => {
          expect(res.body.name).toEqual(updateDto.name);
          expect(res.body.id).toEqual(existingUser.id);
        });
    });

    it('/users/:id (DELETE) - should delete a user', async () => {
      await request(app.getHttpServer()).delete(`/users/${existingUser.id}`).expect(200);
      return request(app.getHttpServer()).get(`/users/${existingUser.id}`).expect(404);
    });
  });
});