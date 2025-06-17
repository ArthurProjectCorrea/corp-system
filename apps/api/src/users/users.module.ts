import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { User } from './user.entity';
import { UsersService } from './users.service';
import { UsersController } from './users.controller';

@Module({
  imports: [TypeOrmModule.forFeature([User])], // Importa a entidade User para este módulo
  providers: [UsersService],
  controllers: [UsersController],
  exports: [UsersService], // Exporte se precisar usar o UsersService em outros módulos
})
export class UsersModule {}
