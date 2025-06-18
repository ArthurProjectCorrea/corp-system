import { Controller, Request, Post, UseGuards, Get, Body, HttpCode, HttpStatus, UnauthorizedException, ValidationPipe } from '@nestjs/common';
import { AuthService } from './auth.service';
import { LocalAuthGuard } from './guards/local-auth.guard';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { IsEmail, IsJWT, IsNotEmpty, IsString } from 'class-validator';

// DTO para o corpo da requisição de login
export class LoginDto {
  @IsString()
  @IsEmail() // Alterado para IsEmail para consistência
  email: string;

  @IsString()
  @IsNotEmpty()
  // Considere adicionar @MinLength para consistência, se desejado.
  password: string; // A senha deve ser obrigatória para login
}

export class RefreshTokenDto {
  @IsString()
  @IsNotEmpty()
  @IsJWT() // Valida se é um formato JWT, embora não valide a assinatura aqui
  refresh_token: string;
}
@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  // @UseGuards(LocalAuthGuard) // Guard removido para permitir que ValidationPipe atue primeiro.
  @Post('login')
  @HttpCode(HttpStatus.OK) // Standard for successful login
  async login(@Body(ValidationPipe) loginDto: LoginDto) {
    const user = await this.authService.validateUser(loginDto.email, loginDto.password);
    if (!user) {
      // Se authService.validateUser retornar null, as credenciais são inválidas.
      throw new UnauthorizedException('Credenciais inválidas');
    }
    return this.authService.login(user); // user aqui é o ValidatedUserPayload
  }

  @UseGuards(JwtAuthGuard)
  @Get('profile')
  getProfile(@Request() req) {
    // req.user é populado pelo JwtAuthGuard após JwtStrategy.validate
    return req.user; // Contém { userId, email, name }
  }

  @Post('refresh')
  @HttpCode(HttpStatus.OK)
  async refresh(@Body() refreshTokenDto: RefreshTokenDto) {
    // A lógica de validação do refresh token e geração de novo access token foi movida para AuthService
    return this.authService.handleRefreshToken(refreshTokenDto.refresh_token);
  }

  @UseGuards(JwtAuthGuard)
  @Post('logout')
  @HttpCode(HttpStatus.OK)
  async logout(@Request() req) {
    // req.user é populado pelo JwtAuthGuard a partir do payload validado do token
    return this.authService.logout(req.user);
  }
}
