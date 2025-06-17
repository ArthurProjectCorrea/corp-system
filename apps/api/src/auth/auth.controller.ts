import { Controller, Request, Post, UseGuards, Get, Body, HttpCode, HttpStatus } from '@nestjs/common';
import { AuthService } from './auth.service';
import { LocalAuthGuard } from './guards/local-auth.guard';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { IsEmail, IsNotEmpty, IsString } from 'class-validator';

// DTO para o corpo da requisição de login
export class LoginDto {
  @IsEmail()
  @IsNotEmpty()
  email: string;

  @IsString()
  @IsNotEmpty()
  // Considere adicionar @MinLength para consistência, se desejado.
  password: string; // A senha deve ser obrigatória para login
}

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @UseGuards(LocalAuthGuard)
  @Post('login')
  @HttpCode(HttpStatus.OK) // Standard for successful login
  async login(@Request() req, @Body() loginDto: LoginDto /* eslint-disable-line @typescript-eslint/no-unused-vars */) {
    // req.user é populado pelo LocalAuthGuard após LocalStrategy.validate
    return this.authService.login(req.user);
  }

  @UseGuards(JwtAuthGuard)
  @Get('profile')
  getProfile(@Request() req) {
    // req.user é populado pelo JwtAuthGuard após JwtStrategy.validate
    return req.user; // Contém { userId, email, name }
  }
}
