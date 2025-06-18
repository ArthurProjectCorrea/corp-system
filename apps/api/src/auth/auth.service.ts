import { Injectable, UnauthorizedException } from '@nestjs/common';
import { UsersService } from '../users/users.service';
import { JwtService } from '@nestjs/jwt';
import { User } from '../users/user.entity';
import { ConfigService } from '@nestjs/config';
import * as bcrypt from 'bcrypt'; // Import bcrypt here if used directly

// Define uma interface para o payload de dados do usuário retornado pela validação
// e esperado pelo método de login. Isso evita problemas com Omit em classes.
interface ValidatedUserPayload {
  id: string;
  name: string;
  email: string;
  createdAt: Date;
  updatedAt: Date;
}
@Injectable()
export class AuthService {
  constructor(
    private usersService: UsersService,
    private jwtService: JwtService,
    private configService: ConfigService,
  ) {}

  async validateUser(email: string, pass: string): Promise<ValidatedUserPayload | null> {
    const user = await this.usersService.findOneWithPassword(email);
    // A propriedade password é opcional em User, mas findOneWithPassword a seleciona.
    // Adicionada verificação de tipo para password para ajudar o TypeScript.
    if (user && typeof user.password === 'string' && (await bcrypt.compare(pass, user.password))) {
      // Constrói explicitamente o objeto de payload
      return {
        id: user.id,
        name: user.name,
        email: user.email,
        createdAt: user.createdAt,
        updatedAt: user.updatedAt,
      };
    }
    return null;
  }

  async login(user: ValidatedUserPayload) {
    const accessTokenPayload = { email: user.email, sub: user.id, name: user.name };
    const refreshTokenPayload = { sub: user.id }; // Refresh token pode ter um payload mais simples

    const accessToken = this.jwtService.sign(accessTokenPayload, {
      secret: this.configService.get<string>('JWT_SECRET'),
      expiresIn: this.configService.get<string>('JWT_EXPIRATION_TIME'),
    });

    const refreshToken = this.jwtService.sign(refreshTokenPayload, {
      secret: this.configService.get<string>('JWT_REFRESH_SECRET'),
      expiresIn: this.configService.get<string>('JWT_REFRESH_EXPIRATION_TIME'),
    });

    return {
      access_token: accessToken,
      refresh_token: refreshToken,
    };
  }

  async refreshToken(userId: string, email: string, name: string) {
    const payload = { email, sub: userId, name };
    return {
      access_token: this.jwtService.sign(payload, {
        secret: this.configService.get<string>('JWT_SECRET'),
        expiresIn: this.configService.get<string>('JWT_EXPIRATION_TIME'),
      }),
    };
  }

  async handleRefreshToken(refreshTokenValue: string): Promise<{ access_token: string }> {
    try {
      const payload = await this.jwtService.verifyAsync(
        refreshTokenValue,
        { secret: this.configService.get<string>('JWT_REFRESH_SECRET') }
      );

      // Busca o usuário para garantir que ele ainda existe e para obter os dados para o novo access token.
      // UsersService.findOne retorna SafeUserOutput, que é Omit<User, 'password_hash'>
      // O tipo SafeUserOutput é definido em UsersService como Omit<User, 'password_hash'>
      const userProfile = await this.usersService.findOne(payload.sub); 
      if (!userProfile) {
        throw new UnauthorizedException('Usuário não encontrado para o token de atualização');
      }
      return this.refreshToken(userProfile.id, userProfile.email, userProfile.name);
    } catch (e) {
      if (e instanceof UnauthorizedException) throw e; // Re-throw se já for UnauthorizedException
      throw new UnauthorizedException('Token de atualização inválido'); // Caso contrário, encapsula o erro
    }
  }
  async logout(userPayload: { userId: string; email: string; name: string }): Promise<{ message: string }> {
    // Para um logout JWT stateless, a ação principal é do lado do cliente (descartar o token).
    // Se uma invalidação de token do lado do servidor (por exemplo, via uma denylist) for necessária,
    // essa lógica seria implementada aqui.
    // Por enquanto, este método apenas acusa o recebimento da solicitação de logout.
    // O userPayload contém os dados validados do token JWT.
    
    // Você pode adicionar logging aqui se desejar, por exemplo:
    // console.log(`User ${userPayload.email} (ID: ${userPayload.userId}) logged out.`);
    return { message: 'Logout successful. Client should discard the token.' };
  }
}
