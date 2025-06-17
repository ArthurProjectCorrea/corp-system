import { Injectable, NotFoundException, ConflictException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from './user.entity';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import * as bcrypt from 'bcrypt';

// Define a type for the user data being returned, excluding password and internal methods.
type SafeUserReturn = Omit<User, 'password' | 'hashPassword'>;

@Injectable()
export class UsersService {
  constructor(
    @InjectRepository(User)
    private usersRepository: Repository<User>,
  ) {}

  // Método para buscar usuário incluindo a senha, usado internamente pela autenticação
  async findOneWithPassword(email: string): Promise<User | null> {
    return this.usersRepository.findOne({ where: { email }, select: ['id', 'name', 'email', 'password', 'createdAt', 'updatedAt'] });
  }

  async create(createUserDto: CreateUserDto): Promise<SafeUserReturn> {
    const existingUser = await this.usersRepository.findOne({ where: { email: createUserDto.email } });
    if (existingUser) {
      throw new ConflictException('Email already exists');
    }
    const userEntity = this.usersRepository.create(createUserDto);
    // A senha já será hasheada pelo hook @BeforeInsert na entidade
    const savedUser = await this.usersRepository.save(userEntity);
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { password, hashPassword, ...result } = savedUser;
    return result;
  }

  async findAll(): Promise<SafeUserReturn[]> {
    const users = await this.usersRepository.find();
    return users.map(userInstance => {
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      const { password, hashPassword, ...user } = userInstance;
      return user;
    });
  }

  async findOne(id: string): Promise<SafeUserReturn> {
    const userInstance = await this.usersRepository.findOne({ where: { id } });
    if (!userInstance) {
      throw new NotFoundException(`User with ID "${id}" not found`);
    }
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { password, hashPassword, ...result } = userInstance;
    return result;
  }

  async update(id: string, updateUserDto: UpdateUserDto): Promise<SafeUserReturn> {
    await this.findOne(id); // Ensures user exists, findOne returns SafeUserReturn
    if (updateUserDto.password) {
      updateUserDto.password = await bcrypt.hash(updateUserDto.password, 10);
    }
    await this.usersRepository.update(id, updateUserDto);
    return this.findOne(id); // Retorna o usuário atualizado sem a senha
  }

  async remove(id: string): Promise<void> {
    const result = await this.usersRepository.delete(id);
    if (result.affected === 0) {
      throw new NotFoundException(`User with ID "${id}" not found`);
    }
  }
}
