import {
  Controller, Post, Body, Param, UseGuards, BadRequestException,
  NotFoundException, UnauthorizedException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { JwtAuthGuard, CurrentUser, AuditClient } from '@campuscast/shared-libs';
import { User } from './user.entity';
import { RequirePermissions } from '../common/require-permissions.decorator';
import { PermissionsGuard } from '../common/permissions.guard';
import * as bcrypt from 'bcrypt';
import * as crypto from 'crypto';

@Controller('users')
@UseGuards(JwtAuthGuard, PermissionsGuard)
export class PasswordController {
  private readonly auditClient: AuditClient;

  constructor(
    @InjectRepository(User) private readonly userRepo: Repository<User>,
  ) {
    this.auditClient = new AuditClient();
  }

  @Post('me/change-password')
  async changeOwnPassword(
    @Body() body: { current_password: string; new_password: string },
    @CurrentUser() actor: { sub: string },
  ) {
    if (!body.current_password || !body.new_password) {
      throw new BadRequestException('Both current_password and new_password are required');
    }
    if (body.new_password.length < 8) {
      throw new BadRequestException('New password must be at least 8 characters');
    }

    const user = await this.userRepo.findOne({ where: { id: actor.sub } });
    if (!user) throw new UnauthorizedException('User not found');

    const valid = await bcrypt.compare(body.current_password, user.password_hash);
    if (!valid) throw new UnauthorizedException('Current password is incorrect');

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
    const user = await this.userRepo.findOne({ where: { id: userId } });
    if (!user) throw new NotFoundException('User not found');

    const tempPassword = body.temporary_password || crypto.randomBytes(12).toString('base64url');
    if (tempPassword.length < 8) {
      throw new BadRequestException('Temporary password must be at least 8 characters');
    }

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
