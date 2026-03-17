import { Controller, Post, Get, Body, HttpCode, Headers, UnauthorizedException } from '@nestjs/common';
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
    return this.authService.refresh(body.refresh_token);
  }

  @Post('validate')
  @HttpCode(200)
  async validate(@Body() body: { token: string }) {
    return this.authService.validateToken(body.token);
  }

  @Get('me')
  async me(@Headers('authorization') authHeader?: string) {
    const token = authHeader?.replace(/^Bearer\s+/i, '');
    if (!token) throw new UnauthorizedException('Missing token');

    const result = await this.authService.validateToken(token);
    if (!result.valid || !result.claims) throw new UnauthorizedException('Invalid token');

    const userId = typeof result.claims === 'object' && 'sub' in result.claims
      ? String(result.claims.sub)
      : undefined;
    if (!userId) throw new UnauthorizedException('Invalid token claims');

    return this.authService.getMe(userId);
  }

  @Post('logout')
  @HttpCode(200)
  async logout() {
    // Stateless JWT — nothing to invalidate server-side.
    // Future: add refresh token revocation list here.
    return { ok: true };
  }
}
