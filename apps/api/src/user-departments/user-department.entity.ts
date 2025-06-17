import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  ManyToOne,
  JoinColumn,
  CreateDateColumn,
  UpdateDateColumn,
} from 'typeorm';
import { User } from '../users/user.entity';
import { Department } from '../departments/department.entity';

export enum AccessLevel {
  ADMIN = 'admin',
  MANAGER = 'manager',
  EMPLOYEE = 'employee',
}

@Entity('user_departments')
export class UserDepartment {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column()
  userId: string;

  @Column()
  departmentId: string;

  @Column({
    type: 'enum',
    enum: AccessLevel,
    default: AccessLevel.EMPLOYEE,
  })
  accessLevel: AccessLevel;

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;

  @ManyToOne(() => User, (user) => user.userDepartments)
  @JoinColumn({ name: 'userId' })
  user: User;

  @ManyToOne(() => Department, (department) => department.userDepartments)
  @JoinColumn({ name: 'departmentId' })
  department: Department;
}