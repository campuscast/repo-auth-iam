import { Controller, Post, Body, HttpCode } from '@nestjs/common';
import { AuthService } from './auth.service';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Post('login')
  @HttpCode(200)
  async login(@Body() body: { email: string; password: string }) {
    return this.authService.login(body.email, body.password);
  }

  @Post('refresh')
  @HttpCode(200)
  async refresh(@Body() body: { refresh_token: string }) {
    const result = await this.authService.validateToken(body.refresh_token);
    if (!result.valid) throw new Error('Invalid refresh token');
    // Stub: issue new tokens
    return { access_token: 'new.access.token', refresh_token: 'new.refresh.token', expires_in: 3600 };
  }

  @Post('validate')
  @HttpCode(200)
  async validate(@Body() body: { token: string }) {
    return this.authService.validateToken(body.token);
  }
}
