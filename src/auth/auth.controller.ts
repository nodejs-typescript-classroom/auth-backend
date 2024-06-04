import { Body, Controller, Post, Put, Req, UseGuards } from '@nestjs/common';
import { AuthService } from './auth.service';
import { SignupDto } from './dtos/signup.dto';
import { LoginDto } from './dtos/login.dto';
import { RefreshTokenDto } from './dtos/refresh-token.dto';
import { ChangePasswordDto } from './dtos/change-password.dto';
import { AuthGuard } from 'src/guards/auth.guard';
import { ForgotPasswordDto } from './dtos/forgot-password.dto';
import { ResetPasswordDto } from './dtos/reset-password.dto';

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
  /**
   * PUT /auth/change-password
   * @param changePasswordDto ChangePasswordDto
   * @param req userId
   * @returns
   */
  @UseGuards(AuthGuard)
  @Put('change-password')
  async changePassword(
    @Body() changePasswordDto: ChangePasswordDto,
    @Req() req,
  ) {
    return this.authService.changePassword(req.userId, changePasswordDto);
  }
  /**
   * Post /auth/forgot-password
   * @param forgotPasswordDto ForgotPasswordDto
   * @returns
   */
  @Post('forgot-password')
  async forgotPassowrd(@Body() forgotPasswordDto: ForgotPasswordDto) {
    return this.authService.forgotPassword(forgotPasswordDto);
  }
  // TODO: Reset Password
  @Put('/reset-password')
  async resetPassword(@Body() resetPasswordDto: ResetPasswordDto) {
    return this.authService.resetPassword(resetPasswordDto);
  }
}
