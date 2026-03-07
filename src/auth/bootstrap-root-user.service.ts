import { Injectable, Logger, OnApplicationBootstrap } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import * as bcrypt from 'bcrypt';
import { Repository } from 'typeorm';
import { Role } from '../roles/role.entity';
import { User } from '../users/user.entity';

@Injectable()
export class BootstrapRootUserService implements OnApplicationBootstrap {
  private readonly logger = new Logger(BootstrapRootUserService.name);

  constructor(
    @InjectRepository(User) private readonly userRepo: Repository<User>,
    @InjectRepository(Role) private readonly roleRepo: Repository<Role>,
  ) {}

  async onApplicationBootstrap(): Promise<void> {
    const enabled = this.parseBoolean(process.env.AUTH_BOOTSTRAP_ROOT_ENABLED, true);
    if (!enabled) {
      this.logger.log('Root bootstrap is disabled');
      return;
    }

    const rootLogin = (process.env.AUTH_BOOTSTRAP_ROOT_EMAIL || 'root').trim();
    const rootPassword = process.env.AUTH_BOOTSTRAP_ROOT_PASSWORD || 'admin';
    const rootRole = (process.env.AUTH_BOOTSTRAP_ROOT_ROLE || 'admin').trim();
    const resetPassword = this.parseBoolean(process.env.AUTH_BOOTSTRAP_ROOT_RESET_PASSWORD, false);

    if (!rootLogin || !rootPassword || !rootRole) {
      throw new Error('AUTH_BOOTSTRAP_ROOT_* variables must be non-empty');
    }

    let role = await this.roleRepo.findOne({ where: { name: rootRole } });
    if (!role) {
      role = this.roleRepo.create({
        name: rootRole,
        permissions: ['*'],
      });
      role = await this.roleRepo.save(role);
      this.logger.log(`Created bootstrap role "${rootRole}"`);
    }

    const user = await this.userRepo.findOne({
      where: { email: rootLogin },
      relations: ['roles'],
    });

    if (!user) {
      const password_hash = await bcrypt.hash(rootPassword, 10);
      const created = this.userRepo.create({
        email: rootLogin,
        password_hash,
        mfa_enabled: false,
        roles: [role],
      });
      await this.userRepo.save(created);
      this.logger.warn(`Bootstrap root user created: "${rootLogin}". Change password after first login.`);
      return;
    }

    let changed = false;

    const hasRole = (user.roles || []).some((assignedRole) => assignedRole.name === rootRole);
    if (!hasRole) {
      user.roles = [...(user.roles || []), role];
      changed = true;
    }

    if (resetPassword) {
      user.password_hash = await bcrypt.hash(rootPassword, 10);
      changed = true;
    }

    if (changed) {
      await this.userRepo.save(user);
      this.logger.warn(`Bootstrap root user updated: "${rootLogin}"`);
      return;
    }

    this.logger.log(`Bootstrap root user already exists: "${rootLogin}"`);
  }

  private parseBoolean(value: string | undefined, defaultValue: boolean): boolean {
    if (value === undefined) return defaultValue;
    const normalized = value.trim().toLowerCase();
    if (['1', 'true', 'yes', 'on'].includes(normalized)) return true;
    if (['0', 'false', 'no', 'off'].includes(normalized)) return false;
    return defaultValue;
  }
}
