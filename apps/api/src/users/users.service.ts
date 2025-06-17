import { Injectable, NotFoundException, ConflictException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { FindOneOptions } from 'typeorm';
import { User } from './user.entity';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import * as bcrypt from 'bcrypt';

// Define a type for the user data being returned, excluding password and internal methods.
type SafeUserOutput = Omit<User, 'password_hash'>;

@Injectable()
export class UsersService {
  constructor(
    @InjectRepository(User)
    private usersRepository: Repository<User>,
  ) {}

  // Método para buscar usuário incluindo a senha hash, usado internamente pela autenticação
  async findOneWithPassword(username: string): Promise<User | null> {
    // Use findOne com select explícito para incluir password_hash
    return this.usersRepository.findOne({
      where: { username },
      select: ['id', 'name', 'username', 'email', 'password_hash', 'createdAt', 'updatedAt', 'deletedAt'],
    });
  }

  async create(createUserDto: CreateUserDto): Promise<SafeUserOutput> {
    const existingUser = await this.usersRepository.findOne({ where: { email: createUserDto.email } });
    if (existingUser) {
      throw new ConflictException('Email already exists');
    }
    const existingUsername = await this.usersRepository.findOne({ where: { username: createUserDto.username } });
    if (existingUsername) {
      throw new ConflictException('Username already exists');
    }

    // Hashear a senha do DTO explicitamente antes de criar a entidade
    const hashedPassword = await bcrypt.hash(createUserDto.password_hash, 10);

    // Cria a entidade usando o repositório e depois define o password_hash hasheado
    const userToSave = this.usersRepository.create({
      ...createUserDto,
      password_hash: hashedPassword, // Usa o hash gerado
    });
    const savedUser = await this.usersRepository.save(userToSave);
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { password_hash, ...result } = savedUser; // Exclui password_hash
    return result;
  }

  async findAll(includeDeleted = false): Promise<SafeUserOutput[]> {
    const findOptions: FindOneOptions<User> = {
        withDeleted: includeDeleted, // Inclui registros com deletedAt se true
    };
    const users = await this.usersRepository.find(findOptions);
    return users.map(userInstance => {
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      const { password_hash, ...user } = userInstance; // Exclui password_hash
      return user;
    });
  }

  async findOne(id: string, includeDeleted = false): Promise<SafeUserOutput> {
     const findOptions: FindOneOptions<User> = {
        where: { id },
        withDeleted: includeDeleted, // Inclui registros com deletedAt se true
    };
    const userInstance = await this.usersRepository.findOne(findOptions);
    if (!userInstance) {
      throw new NotFoundException(`User with ID "${id}" not found`);
    }
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { password_hash, ...result } = userInstance; // Exclui password_hash
    return result;
  }

  async update(id: string, updateUserDto: UpdateUserDto): Promise<SafeUserOutput> {
    // Verifica se o usuário existe, mesmo que tenha sido soft-deletado.
    const userToUpdate = await this.findOne(id, true); 

    if (updateUserDto.username) {
        const existingUsername = await this.usersRepository.findOne({ where: { username: updateUserDto.username } });
        // Check if the found user is not the user being updated
        if (existingUsername && existingUsername.id !== id) {
             throw new ConflictException('Username already exists');
        }
    }
    if (updateUserDto.password_hash) { // Verifica se password_hash foi fornecido
      updateUserDto.password_hash = await bcrypt.hash(updateUserDto.password_hash, 10);
    }
    await this.usersRepository.update(id, updateUserDto);
    // Retorna o usuário atualizado, respeitando seu estado original de soft-delete.
    return this.findOne(id, !!userToUpdate.deletedAt); 
  }

  async remove(id: string): Promise<void> {
    // Garante que o usuário exista e esteja ativo antes de tentar o soft delete.
    // this.findOne(id) já lança NotFoundException se o usuário não estiver ativo.
    await this.findOne(id);

    const result = await this.usersRepository.softDelete(id);
    if (result.affected === 0) {
      // Este caso pode ocorrer se o usuário for deletado entre a verificação e o softDelete,
      // ou se o softDelete em si falhar.
      throw new NotFoundException(`User with ID "${id}" not found`);
    }
  }
}
