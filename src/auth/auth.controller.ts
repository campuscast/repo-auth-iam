import { Controller, Post, Get, Body, HttpCode, Headers, UnauthorizedException, UseGuards } from '@nestjs/common';
import { CurrentUser, JwtAuthGuard } from '@campuscast/shared-libs';
import { AuthService } from './auth.service';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Post('login')
  @HttpCode(200)
  async login(@Body() body: { email: string; password: string }) {
    return this.authService.login(body.email, body.password);
  }

  @Post('mfa/login-verify')
  @HttpCode(200)
  async verifyMfaLogin(@Body() body: { mfa_token: string; code: string }) {
    return this.authService.verifyMfaLogin(body.mfa_token, body.code);
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

  @Get('mfa/status')
  @UseGuards(JwtAuthGuard)
  async mfaStatus(@CurrentUser() user: { sub: string }) {
    return this.authService.getMfaStatus(user.sub);
  }

  @Post('mfa/setup')
  @UseGuards(JwtAuthGuard)
  async mfaSetup(@CurrentUser() user: { sub: string }) {
    return this.authService.initiateMfaSetup(user.sub);
  }

  @Post('mfa/verify')
  @UseGuards(JwtAuthGuard)
  @HttpCode(200)
  async mfaVerify(@CurrentUser() user: { sub: string }, @Body() body: { code: string }) {
    return this.authService.verifyMfaCode(user.sub, body.code);
  }

  @Post('mfa/enable')
  @UseGuards(JwtAuthGuard)
  @HttpCode(200)
  async mfaEnable(@CurrentUser() user: { sub: string }, @Body() body: { code: string }) {
    return this.authService.enableMfa(user.sub, body.code);
  }

  @Post('mfa/disable')
  @UseGuards(JwtAuthGuard)
  @HttpCode(200)
  async mfaDisable(@CurrentUser() user: { sub: string }, @Body() body: { password: string }) {
    return this.authService.disableMfa(user.sub, body.password);
  }

  @Post('logout')
  @HttpCode(200)
  async logout() {
    // Stateless JWT — nothing to invalidate server-side.
    // Future: add refresh token revocation list here.
    return { ok: true };
  }
}
