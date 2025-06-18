import { Strategy } from 'passport-local';
import { PassportStrategy } from '@nestjs/passport';
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { AuthService } from '../auth.service';
import { User } from '../../users/user.entity'; // Import User type if needed for return type hint

// Define ou importa o mesmo payload que AuthService.validateUser retorna
interface ValidatedUserPayload {
  id: string;
  email: string;
  name: string;
  createdAt: Date;
  updatedAt: Date;
}
@Injectable()
export class LocalStrategy extends PassportStrategy(Strategy) {
  constructor(private authService: AuthService) {
    super({ usernameField: 'email' }); // Alterado para 'email'
  }

  async validate(email: string, pass: string): Promise<ValidatedUserPayload> {
    const user = await this.authService.validateUser(email, pass);
    if (!user) {
      throw new UnauthorizedException('Credenciais inválidas');
    }
    return user; 
  }
}