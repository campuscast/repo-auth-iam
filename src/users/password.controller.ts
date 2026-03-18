import {
  Controller, Post, Body, Param, UseGuards, BadRequestException,
  NotFoundException, UnauthorizedException, ForbiddenException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { JwtAuthGuard, CurrentUser, AuditClient } from '@campuscast/shared-libs';
import { User } from './user.entity';
import { RequirePermissions } from '../common/require-permissions.decorator';
import { PermissionsGuard } from '../common/permissions.guard';
import * as bcrypt from 'bcrypt';
import * as crypto from 'crypto';
import { assertPasswordPolicy } from '../auth/password-policy';

@Controller('users')
@UseGuards(JwtAuthGuard, PermissionsGuard)
export class PasswordController {
  private readonly auditClient: AuditClient;

  constructor(
    @InjectRepository(User) private readonly userRepo: Repository<User>,
  ) {
    this.auditClient = new AuditClient();
  }

  private isSuperAdminUser(user: User): boolean {
    return (user.roles || []).some((role) => role.name === 'super_admin');
  }

  @Post('me/change-password')
  async changeOwnPassword(
    @Body() body: { current_password?: string; new_password?: string },
    @CurrentUser() actor: { sub: string },
  ) {
    if (!body?.new_password) {
      throw new BadRequestException('new_password is required');
    }
    assertPasswordPolicy(body.new_password, 'New password');

    const user = await this.userRepo.findOne({ where: { id: actor.sub } });
    if (!user) throw new UnauthorizedException('User not found');

    if (!user.must_change_password) {
      if (!body.current_password) {
        throw new BadRequestException('current_password is required');
      }

      const valid = await bcrypt.compare(body.current_password, user.password_hash);
      if (!valid) throw new UnauthorizedException('Current password is incorrect');
    }

    user.password_hash = await bcrypt.hash(body.new_password, 10);
    user.must_change_password = false;
    await this.userRepo.save(user);

    this.auditClient.append({
      event_type: 'iam.password_changed',
      actor_type: 'user',
      actor_id: actor.sub,
      resource_type: 'user',
      resource_id: actor.sub,
      action: 'change_password',
      detail: { self: true },
    });

    return { ok: true, message: 'Password changed successfully' };
  }

  @Post(':id/reset-password')
  @RequirePermissions('users.write')
  async adminResetPassword(
    @Param('id') userId: string,
    @Body() body: { temporary_password?: string },
    @CurrentUser() actor: { sub: string },
  ) {
    const user = await this.userRepo.findOne({ where: { id: userId }, relations: ['roles'] });
    if (!user) throw new NotFoundException('User not found');
    if (this.isSuperAdminUser(user)) {
      throw new ForbiddenException('Cannot reset password for super_admin user via users management');
    }

    const tempPassword = body.temporary_password || crypto.randomBytes(12).toString('base64url');
    assertPasswordPolicy(tempPassword, 'Temporary password');

    user.password_hash = await bcrypt.hash(tempPassword, 10);
    user.must_change_password = true;
    await this.userRepo.save(user);

    this.auditClient.append({
      event_type: 'iam.password_reset_by_admin',
      actor_type: 'user',
      actor_id: actor.sub,
      resource_type: 'user',
      resource_id: userId,
      action: 'admin_reset_password',
      detail: { target_email: user.email },
    });

    return {
      ok: true,
      temporary_password: tempPassword,
      message: 'Password reset. User must change password on next login.',
    };
  }
}
