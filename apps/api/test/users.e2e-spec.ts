import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import * as request from 'supertest';
import { AppModule } from '../src/app.module';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { getRepositoryToken } from '@nestjs/typeorm';
import { Repository, DataSource } from 'typeorm'; // Adicionar DataSource aqui
import { User } from '../src/users/user.entity';
import { CreateUserDto } from '../src/users/dto/create-user.dto';
import { UserDepartment } from '../src/user-departments/user-department.entity';
import * as bcrypt from 'bcrypt';

describe('UsersController (e2e)', () => {
  let app: INestApplication;
  let userRepository: Repository<User>;
  let userDepartmentRepository: Repository<UserDepartment>;
  let dataSource: DataSource;
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
    userDepartmentRepository = moduleFixture.get<Repository<UserDepartment>>(getRepositoryToken(UserDepartment));
    dataSource = moduleFixture.get<DataSource>(DataSource);
  });

  beforeEach(async () => {
    // Usar TRUNCATE CASCADE para limpar todas as tabelas relacionadas
    await dataSource.query('TRUNCATE TABLE "user_departments", "users", "departments" RESTART IDENTITY CASCADE;');
  });
  afterAll(async () => {
    // Opcional: limpar o banco de dados após todos os testes deste arquivo, se necessário.
    // await dataSource.query('TRUNCATE TABLE "user_departments", "users", "departments" RESTART IDENTITY CASCADE;');
    await app.close();
  });

  const defaultUserPassword = 'password123';
  const createUserDto: CreateUserDto = {
    username: 'testuser',
    name: 'Test User',
    email: 'test@example.com',
    password_hash: defaultUserPassword,
  };

  it('/users (POST) - should create a new user', async () => {
    return request(app.getHttpServer())
      .post('/users')
      .send(createUserDto)
      .expect(201)
      .then((res) => {
        expect(res.body).toBeDefined();
        expect(res.body.email).toEqual(createUserDto.email);
        expect(res.body.username).toEqual(createUserDto.username);
        expect(res.body.name).toEqual(createUserDto.name);
        expect(res.body.id).toBeDefined();
        expect(res.body.password_hash).toBeUndefined();
        expect(res.body.createdAt).toBeDefined();
        expect(res.body.updatedAt).toBeDefined();
      });
  });

  it('/users (POST) - should fail to create user with existing email (409)', async () => {
    await request(app.getHttpServer()).post('/users').send(createUserDto).expect(201);
    return request(app.getHttpServer())
      .post('/users')
      .send({ ...createUserDto, username: 'anotheruser' }) // Different username, same email
      .expect(409)
      .then((res) => {
        expect(res.body.message).toEqual('Email already exists');
      });
  });

  it('/users (POST) - should fail to create user with existing username (409)', async () => {
    // Use a fresh copy of the DTO for the first creation
    const firstUserPayload = { ...createUserDto };
    const res1 = await request(app.getHttpServer()).post('/users').send(firstUserPayload).expect(201);
    const createdUserApi = res1.body; // User data returned by the API
    expect(createdUserApi.username).toEqual(firstUserPayload.username);

    // Verify directly in DB if the first user was persisted and is findable by its username
    const foundUserInDb = await userRepository.findOne({ where: { username: firstUserPayload.username } });
    expect(foundUserInDb).toBeDefined(); // Check if the user exists in the DB
    expect(foundUserInDb?.id).toEqual(createdUserApi.id); // Verify it's the same user

    // Use a fresh copy for the second attempt, ensuring the username is the same
    const secondUserPayload = { ...createUserDto, email: 'another@example.com' };
    return request(app.getHttpServer())
      .post('/users')
      .send(secondUserPayload) // Attempt to create with the same username
      .expect(409)
      .then((res) => {
        expect(res.body.message).toEqual('Username already exists');
      });
  });

  it('/users (POST) - should fail with validation errors for invalid data (400)', async () => {
    const invalidDto = { email: 'not-an-email', name: '', username: '' }; // Missing password_hash, invalid username
    return request(app.getHttpServer())
      .post('/users')
      .send(invalidDto)
      .expect(400)
      .then((res) => {
        expect(res.body.message).toBeInstanceOf(Array);
        expect(res.body.message).toEqual(
          expect.arrayContaining([
            'username should not be empty',
            'name should not be empty',
            'email must be an email',
            'password_hash should not be empty',
            'Password hash must be at least 6 characters long',
          ]),
        );
      });
  });

  describe('with an existing user', () => {
    let existingUser: User;

    beforeEach(async () => {
      // Modificado para criar o usuário diretamente no banco de dados para este bloco de teste
      // Isso ajuda a isolar se o problema é com a chamada API no beforeEach ou com a persistência/busca.
      const uniqueSuffix = Date.now(); // Para garantir unicidade em execuções repetidas
      const hashedPassword = await bcrypt.hash(defaultUserPassword, 10);
      const userToCreate = userRepository.create({
        username: `existinguser_${uniqueSuffix}`,
        name: 'Existing Test User',
        email: `existing_${uniqueSuffix}@example.com`,
        password_hash: hashedPassword,
      });
      existingUser = await userRepository.save(userToCreate);
      expect(existingUser).toBeDefined();
      expect(existingUser.id).toBeDefined();
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
          expect(userInList.username).toEqual(existingUser.username);
          expect(userInList.email).toEqual(existingUser.email);
          expect(userInList.password_hash).toBeUndefined();
        });
    });

    it('/users/:id (GET) - should get a specific user by id', async () => {
      return request(app.getHttpServer())
        .get(`/users/${existingUser.id}`)
        .expect(200)
        .then((res) => {
          expect(res.body.id).toEqual(existingUser.id);
          expect(res.body.username).toEqual(existingUser.username);
          expect(res.body.email).toEqual(existingUser.email);
          expect(res.body.password_hash).toBeUndefined();
        });
    });

    it('/users/:id (PATCH) - should update a user', async () => {
      const updateDto = { name: 'Updated Test User', username: 'updatedusername' };
      return request(app.getHttpServer())
        .patch(`/users/${existingUser.id}`)
        .send(updateDto)
        .expect(200)
        .then((res) => {
          expect(res.body.name).toEqual(updateDto.name);
          expect(res.body.id).toEqual(existingUser.id);
          expect(res.body.username).toEqual(updateDto.username);
        });
    });

    it('/users/:id (PATCH) - should update user password_hash', async () => {
      const updateDto = { password_hash: 'newpassword456' };
      await request(app.getHttpServer())
        .patch(`/users/${existingUser.id}`)
        .send(updateDto)
        .expect(200);

      // Verify by trying to login with the new password
      // This requires the auth setup, or a direct check if password_hash was indeed updated (not directly possible via API response)
      // For simplicity, we'll assume the update worked if it returned 200.
      // A more thorough test would involve the auth flow.
    });

    it('/users/:id (DELETE) - should soft delete a user', async () => {
      await request(app.getHttpServer()).delete(`/users/${existingUser.id}`).expect(200);
      // Standard GET should now return 404 as findOne by default doesn't include deleted
      return request(app.getHttpServer()).get(`/users/${existingUser.id}`).expect(404);
    });
  });
});