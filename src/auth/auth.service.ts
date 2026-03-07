import {Injectable, UnauthorizedException} from '@nestjs/common'
import {InjectRepository} from '@nestjs/typeorm'
import {Repository} from 'typeorm'
import {User} from '../users/user.entity'
import {UserZoneAssignment} from '../users/user-zone-assignment.entity'
import * as bcrypt from 'bcrypt'
import jwt from 'jsonwebtoken'

@Injectable()
export class AuthService {
  constructor(
    @InjectRepository(User) private userRepo: Repository<User>,
    @InjectRepository(UserZoneAssignment) private uzaRepo: Repository<UserZoneAssignment>,
  ) {}

  async login(email: string, password: string) {
    const user = await this.userRepo.findOne({ where: { email } });
    if (!user) throw new UnauthorizedException('Invalid credentials');

    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) throw new UnauthorizedException('Invalid credentials');

    const assignments = await this.uzaRepo.find({ where: { user_id: user.id } });
    const zone_ids = assignments.map(a => a.zone_id);
    const roles = user.roles.map(r => r.name);

    const secret = process.env.JWT_SECRET || 'dev-secret-change-in-production';
    const expiresInSec = parseInt(process.env.JWT_EXPIRY_SECONDS || '3600', 10);
    const access_token = jwt.sign(
      { sub: user.id, email: user.email, roles, zone_ids, mfa_verified: !user.mfa_enabled },
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

  async refresh(refreshToken: string) {
    const secret = process.env.JWT_SECRET || 'dev-secret-change-in-production';
    let payload: jwt.JwtPayload;
    try {
      payload = jwt.verify(refreshToken, secret) as jwt.JwtPayload;
    } catch {
      throw new UnauthorizedException('Invalid refresh token');
    }
    if (payload.type !== 'refresh' || !payload.sub) {
      throw new UnauthorizedException('Invalid refresh token');
    }

    const user = await this.userRepo.findOne({ where: { id: String(payload.sub) } });
    if (!user) throw new UnauthorizedException('User not found');

    const assignments = await this.uzaRepo.find({ where: { user_id: user.id } });
    const zone_ids = assignments.map(a => a.zone_id);
    const roles = user.roles.map(r => r.name);
    const expiresInSec = parseInt(process.env.JWT_EXPIRY_SECONDS || '3600', 10);
    const access_token = jwt.sign(
      { sub: user.id, email: user.email, roles, zone_ids, mfa_verified: !user.mfa_enabled },
      secret,
      { expiresIn: expiresInSec },
    );
    const new_refresh_token = jwt.sign(
      { sub: user.id, type: 'refresh' },
      secret,
      { expiresIn: 7 * 24 * 3600 },
    );
    return { access_token, refresh_token: new_refresh_token, expires_in: expiresInSec };
  }

  async validateToken(token: string) {
    const secret = process.env.JWT_SECRET || 'dev-secret-change-in-production';
    try {
      const payload = jwt.verify(token, secret);
      return { valid: true, claims: payload };
    } catch {
      return { valid: false, claims: null };
    }
  }
}
