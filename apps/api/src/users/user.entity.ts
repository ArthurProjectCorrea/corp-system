import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  UpdateDateColumn,
  DeleteDateColumn,
  BeforeInsert,
  OneToMany,
} from 'typeorm';
import * as bcrypt from 'bcrypt';
import { UserDepartment } from '../user-departments/user-department.entity';

@Entity('users') // Define o nome da tabela no banco de dados como 'users'
export class User {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ length: 100 })
  name: string;

  @Column({ unique: true, length: 50 })
  username: string;

  @Column({ unique: true, length: 100 })
  email: string;

  @Column()
  password_hash?: string; // O '?' torna opcional para não ser retornado sempre

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;

  @DeleteDateColumn()
  deletedAt?: Date; // Para soft delete

  @OneToMany(() => UserDepartment, (userDepartment) => userDepartment.user)
  userDepartments: UserDepartment[];

  // // O Hashing agora é feito no UsersService.create
  // @BeforeInsert()
  // async hashPassword() {
  //   if (this.password_hash) {
  //     const saltRounds = 10;
  //     this.password_hash = await bcrypt.hash(this.password_hash, saltRounds);
  //   }
  // }
}
