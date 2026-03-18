import { BadRequestException, Injectable, UnauthorizedException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { randomBytes } from 'crypto';
import * as bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { RedisService } from '@campuscast/shared-libs';
import { User } from '../users/user.entity';
import { UserZoneAssignment } from '../users/user-zone-assignment.entity';
import { buildOtpAuthUri, generateTotpSecret, verifyTotpCode } from './totp.util';

type TokenPairResponse = {
  access_token: string;
  refresh_token: string;
  expires_in: number;
};

type MfaChallengeResponse = {
  mfa_required: true;
  mfa_token: string;
  expires_in: number;
};

type MfaChallengeState = {
  user_id: string;
  expires_at_ms: number;
};

@Injectable()
export class AuthService {
  private readonly onlineTtlSeconds = Math.max(
    20,
    parseInt(process.env.AUTH_ONLINE_TTL_SECONDS || '60', 10) || 60,
  );
  private readonly mfaChallengeStore = new Map<string, MfaChallengeState>();
  private readonly mfaChallengeTtlSeconds = Math.max(
    60,
    parseInt(process.env.MFA_CHALLENGE_TTL_SECONDS || '300', 10) || 300,
  );
  private readonly mfaIssuer = process.env.MFA_ISSUER || 'CampusCast';

  constructor(
    @InjectRepository(User) private userRepo: Repository<User>,
    @InjectRepository(UserZoneAssignment) private uzaRepo: Repository<UserZoneAssignment>,
    private readonly redisService: RedisService,
  ) {}

  private onlineKey(userId: string): string {
    return `auth:online:user:${userId}`;
  }

  private revokedKey(userId: string): string {
    return `auth:revoked:user:${userId}`;
  }

  private async touchOnline(userId: string) {
    try {
      await this.redisService.client.set(
        this.onlineKey(userId),
        String(Date.now()),
        'EX',
        this.onlineTtlSeconds,
      );
    } catch {
      // Presence is best-effort.
    }
  }

  private async clearOnline(userId: string) {
    try {
      await this.redisService.client.del(this.onlineKey(userId));
    } catch {
      // Presence is best-effort.
    }
  }

  private async clearRevoked(userId: string) {
    try {
      await this.redisService.client.del(this.revokedKey(userId));
    } catch {
      // Revocation cache cleanup is best-effort.
    }
  }

  private async isRevoked(userId: string): Promise<boolean> {
    try {
      const exists = await this.redisService.client.exists(this.revokedKey(userId));
      return exists > 0;
    } catch {
      return false;
    }
  }

  private getSecret(): string {
    const secret = process.env.JWT_SECRET;
    if (!secret && process.env.NODE_ENV === 'production') {
      throw new Error('JWT_SECRET must be set in production');
    }
    return secret || 'dev-secret-change-in-production';
  }

  private collectPermissions(roles: { name: string; permissions: string[] }[]): string[] {
    const perms = new Set<string>();
    for (const role of roles) {
      for (const p of role.permissions || []) {
        perms.add(p);
      }
    }
    return [...perms];
  }

  private cleanupExpiredMfaChallenges() {
    const now = Date.now();
    for (const [token, challenge] of this.mfaChallengeStore.entries()) {
      if (challenge.expires_at_ms <= now) {
        this.mfaChallengeStore.delete(token);
      }
    }
  }

  private createMfaChallenge(userId: string): MfaChallengeResponse {
    this.cleanupExpiredMfaChallenges();
    const token = randomBytes(32).toString('base64url');
    const expiresAt = Date.now() + this.mfaChallengeTtlSeconds * 1000;
    this.mfaChallengeStore.set(token, { user_id: userId, expires_at_ms: expiresAt });
    return { mfa_required: true, mfa_token: token, expires_in: this.mfaChallengeTtlSeconds };
  }

  private consumeMfaChallenge(mfaToken: string): string {
    this.cleanupExpiredMfaChallenges();
    const token = String(mfaToken || '');
    const challenge = this.mfaChallengeStore.get(token);
    this.mfaChallengeStore.delete(token);
    if (!challenge || challenge.expires_at_ms <= Date.now()) {
      throw new UnauthorizedException('MFA challenge expired');
    }
    return challenge.user_id;
  }

  private async buildAuthContext(user: User) {
    const assignments = await this.uzaRepo.find({ where: { user_id: user.id } });
    const zone_ids = assignments.map((a) => a.zone_id);
    const roles = user.roles.map((r) => r.name);
    const permissions = this.collectPermissions(user.roles);
    return { zone_ids, roles, permissions };
  }

  private signTokenPair(user: User, context: { zone_ids: string[]; roles: string[]; permissions: string[] }, mfaVerified: boolean): TokenPairResponse {
    const secret = this.getSecret();
    const expiresInSec = parseInt(process.env.JWT_EXPIRY_SECONDS || '3600', 10);
    const access_token = jwt.sign(
      {
        sub: user.id,
        email: user.email,
        roles: context.roles,
        permissions: context.permissions,
        zone_ids: context.zone_ids,
        mfa_verified: mfaVerified,
      },
      secret,
      { expiresIn: expiresInSec },
    );
    const refresh_token = jwt.sign(
      { sub: user.id, type: 'refresh' },
      secret,
      { expiresIn: 7 * 24 * 3600 },
    );

    return { access_token, refresh_token, expires_in: expiresInSec };
  }

  private async issueTokenPair(user: User, mfaVerified: boolean): Promise<TokenPairResponse> {
    await this.clearRevoked(user.id);
    await this.touchOnline(user.id);
    const context = await this.buildAuthContext(user);
    return this.signTokenPair(user, context, mfaVerified);
  }

  async login(email: string, password: string): Promise<TokenPairResponse | MfaChallengeResponse> {
    const user = await this.userRepo.findOne({ where: { email } });
    if (!user) throw new UnauthorizedException('Invalid credentials');
    if (user.status !== 'active') throw new UnauthorizedException('Account is deactivated');

    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) throw new UnauthorizedException('Invalid credentials');

    if (user.mfa_enabled) {
      if (!user.mfa_secret) {
        throw new UnauthorizedException('MFA is not configured');
      }
      return this.createMfaChallenge(user.id);
    }

    return this.issueTokenPair(user, true);
  }

  async verifyMfaLogin(mfaToken: string, code: string): Promise<TokenPairResponse> {
    const userId = this.consumeMfaChallenge(mfaToken);
    const user = await this.userRepo.findOne({ where: { id: userId } });
    if (!user) throw new UnauthorizedException('Session revoked by administrator');
    if (user.status !== 'active') throw new UnauthorizedException('Account is deactivated');
    if (!user.mfa_enabled || !user.mfa_secret) {
      throw new UnauthorizedException('MFA is not enabled');
    }

    const ok = verifyTotpCode(user.mfa_secret, code, { window: 1 });
    if (!ok) throw new UnauthorizedException('Invalid MFA code');

    return this.issueTokenPair(user, true);
  }

  async refresh(refreshToken: string) {
    const secret = this.getSecret();
    let payload: jwt.JwtPayload;
    try {
      payload = jwt.verify(refreshToken, secret) as jwt.JwtPayload;
    } catch {
      throw new UnauthorizedException('Invalid refresh token');
    }
    if (payload.type !== 'refresh' || !payload.sub) {
      throw new UnauthorizedException('Invalid refresh token');
    }

    const userId = String(payload.sub);
    if (await this.isRevoked(userId)) {
      await this.clearOnline(userId);
      throw new UnauthorizedException('Session revoked by administrator');
    }

    const user = await this.userRepo.findOne({ where: { id: userId } });
    if (!user) throw new UnauthorizedException('Session revoked by administrator');
    if (user.status !== 'active') throw new UnauthorizedException('Account is deactivated');

    return this.issueTokenPair(user, true);
  }

  async validateToken(token: string) {
    const secret = this.getSecret();
    try {
      const payload = jwt.verify(token, secret);
      return { valid: true, claims: payload };
    } catch {
      return { valid: false, claims: null };
    }
  }

  async getMe(userId: string) {
    if (await this.isRevoked(userId)) {
      await this.clearOnline(userId);
      throw new UnauthorizedException('Session revoked by administrator');
    }

    const user = await this.userRepo.findOne({ where: { id: userId } });
    if (!user) throw new UnauthorizedException('Session revoked by administrator');
    if (user.status !== 'active') {
      await this.clearOnline(user.id);
      throw new UnauthorizedException('You have been disabled by administrator');
    }
    if (await this.isRevoked(user.id)) {
      await this.clearOnline(user.id);
      throw new UnauthorizedException('Session revoked by administrator');
    }

    await this.touchOnline(user.id);

    const assignments = await this.uzaRepo.find({ where: { user_id: user.id } });
    const zones = assignments.map((a) => a.zone_id);
    const roles = user.roles.map((r) => r.name);
    const permissions = this.collectPermissions(user.roles);

    return {
      user: {
        id: user.id,
        email: user.email,
        name: user.name || user.email,
        must_change_password: user.must_change_password,
      },
      roles,
      permissions,
      zones,
      mfa_enabled: user.mfa_enabled,
      crdt_enabled: false,
    };
  }

  async getMfaStatus(userId: string) {
    const user = await this.userRepo.findOne({ where: { id: userId } });
    if (!user) throw new UnauthorizedException('User not found');
    return {
      mfa_enabled: user.mfa_enabled,
      has_secret: Boolean(user.mfa_secret),
    };
  }

  async initiateMfaSetup(userId: string) {
    const user = await this.userRepo.findOne({ where: { id: userId } });
    if (!user) throw new UnauthorizedException('User not found');
    if (user.mfa_enabled) {
      throw new BadRequestException('MFA already enabled. Disable MFA first to reconfigure.');
    }

    const secret = generateTotpSecret();
    user.mfa_secret = secret;
    await this.userRepo.save(user);

    return {
      secret,
      issuer: this.mfaIssuer,
      account_name: user.email,
      otpauth_uri: buildOtpAuthUri({
        issuer: this.mfaIssuer,
        accountName: user.email,
        secret,
      }),
    };
  }

  async verifyMfaCode(userId: string, code: string) {
    const user = await this.userRepo.findOne({ where: { id: userId } });
    if (!user) throw new UnauthorizedException('User not found');
    if (!user.mfa_secret) throw new BadRequestException('MFA setup is not initialized');

    const valid = verifyTotpCode(user.mfa_secret, code, { window: 1 });
    if (!valid) throw new BadRequestException('Invalid MFA code');

    return { ok: true, valid: true };
  }

  async enableMfa(userId: string, code: string) {
    const user = await this.userRepo.findOne({ where: { id: userId } });
    if (!user) throw new UnauthorizedException('User not found');
    if (!user.mfa_secret) throw new BadRequestException('MFA setup is not initialized');

    const valid = verifyTotpCode(user.mfa_secret, code, { window: 1 });
    if (!valid) throw new BadRequestException('Invalid MFA code');

    user.mfa_enabled = true;
    await this.userRepo.save(user);
    return { ok: true, mfa_enabled: true };
  }

  async disableMfa(userId: string, password: string) {
    const user = await this.userRepo.findOne({ where: { id: userId } });
    if (!user) throw new UnauthorizedException('User not found');
    if (!user.mfa_enabled) return { ok: true, mfa_enabled: false };
    if (!password) throw new BadRequestException('Password is required to disable MFA');

    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) throw new UnauthorizedException('Invalid password');

    user.mfa_enabled = false;
    user.mfa_secret = null;
    await this.userRepo.save(user);

    for (const [token, challenge] of this.mfaChallengeStore.entries()) {
      if (challenge.user_id === userId) {
        this.mfaChallengeStore.delete(token);
      }
    }

    return { ok: true, mfa_enabled: false };
  }
}
