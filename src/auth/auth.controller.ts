import { Body, Controller, Post } from '@nestjs/common';
import { AuthService } from './auth.service';
import { SignupDto } from './dtos/signup.dto';
import { LoginDto } from './dtos/login.dto';
import { RefreshTokenDto } from './dtos/refresh-token.dto';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  /**
   * POST /auth/signup
   * @param signupData SignupDto
   * @returns
   */
  @Post('signup')
  async signUp(@Body() signupData: SignupDto) {
    return this.authService.signup(signupData);
  }

  /**
   * POST /auth/login
   * @param loginData LoginDto
   * @returns {accessToken: string, refreshToken: string, userId: string}
   */
  @Post('login')
  async login(@Body() loginData: LoginDto) {
    return this.authService.login(loginData);
  }

  /**
   * POST /auth/refresh
   * @param refreshTokenData /auth/refresh
   * @returns {accessToken: string, refreshToken: string}
   */
  @Post('refresh')
  async refresh(@Body() refreshTokenData: RefreshTokenDto) {
    return this.authService.refreshTokens(refreshTokenData);
  }
}
