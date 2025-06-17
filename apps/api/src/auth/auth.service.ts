import { Injectable } from '@nestjs/common';
import { UsersService } from '../users/users.service';
import { JwtService } from '@nestjs/jwt';
import { User } from '../users/user.entity';
import * as bcrypt from 'bcrypt'; // Import bcrypt here if used directly

@Injectable()
export class AuthService {
  constructor(
    private usersService: UsersService,
    private jwtService: JwtService,
  ) {}

  async validateUser(username: string, pass: string): Promise<Omit<User, 'password_hash' | 'hashPassword'> | null> {
    const user = await this.usersService.findOneWithPassword(username);
    if (user && user.password_hash && (await bcrypt.compare(pass, user.password_hash))) {
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      const { password_hash, ...result } = user; // Exclui password_hash
      return result;
    }
    return null;
  }

  async login(user: Omit<User, 'password_hash' | 'hashPassword'>) {
    const payload = { username: user.username, sub: user.id, name: user.name }; // Usa username no payload
    return {
      access_token: this.jwtService.sign(payload),
    };
  }
}
