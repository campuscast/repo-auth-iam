import { Injectable, Logger, OnApplicationBootstrap } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import * as bcrypt from 'bcrypt';
import { Repository } from 'typeorm';
import { Role } from '../roles/role.entity';
import { User } from '../users/user.entity';
import { SystemSetting } from '../system/system-setting.entity';

@Injectable()
export class BootstrapRootUserService implements OnApplicationBootstrap {
  private readonly logger = new Logger(BootstrapRootUserService.name);

  constructor(
    @InjectRepository(User) private readonly userRepo: Repository<User>,
    @InjectRepository(Role) private readonly roleRepo: Repository<Role>,
    @InjectRepository(SystemSetting) private readonly settingRepo: Repository<SystemSetting>,
  ) {}

  async onApplicationBootstrap(): Promise<void> {
    // Seed default roles if they don't exist
    await this.seedDefaultRoles();

    const enabled = this.parseBoolean(
      process.env.AUTH_BOOTSTRAP_ROOT_ENABLED ?? process.env.AUTH_BOOTSTRAP_ADMIN_ENABLED,
      false,
    );
    if (!enabled) {
      this.logger.log('Bootstrap admin on startup is disabled');
      return;
    }

    const rootLogin = (
      process.env.AUTH_BOOTSTRAP_ROOT_EMAIL ??
      process.env.AUTH_BOOTSTRAP_ADMIN_EMAIL ??
      ''
    ).trim();
    const rootPassword =
      process.env.AUTH_BOOTSTRAP_ROOT_PASSWORD ??
      process.env.AUTH_BOOTSTRAP_ADMIN_PASSWORD ??
      '';
    const rootRole = (
      process.env.AUTH_BOOTSTRAP_ROOT_ROLE ??
      process.env.AUTH_BOOTSTRAP_ADMIN_ROLE ??
      'admin'
    ).trim();
    const resetPassword = this.parseBoolean(
      process.env.AUTH_BOOTSTRAP_ROOT_RESET_PASSWORD ??
        process.env.AUTH_BOOTSTRAP_ADMIN_RESET_PASSWORD,
      false,
    );

    if (!rootLogin || !rootPassword) {
      this.logger.error(
        'AUTH_BOOTSTRAP_ADMIN_EMAIL and AUTH_BOOTSTRAP_ADMIN_PASSWORD must be non-empty when startup bootstrap is enabled. ' +
          'Skipping admin bootstrap.',
      );
      return;
    }

    if (rootLogin === 'root' && rootPassword === 'admin') {
      this.logger.error(
        'Insecure default credentials (root/admin) are not allowed. ' +
          'Set AUTH_BOOTSTRAP_ADMIN_EMAIL and AUTH_BOOTSTRAP_ADMIN_PASSWORD to secure values.',
      );
      return;
    }

    if (!rootRole) {
      throw new Error('AUTH_BOOTSTRAP_ROOT_ROLE must be non-empty');
    }

    let role = await this.roleRepo.findOne({ where: { name: rootRole } });
    if (!role) {
      role = this.roleRepo.create({
        name: rootRole,
        permissions: ['*'],
      });
      role = await this.roleRepo.save(role);
      this.logger.log(`Created bootstrap admin role "${rootRole}"`);
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
        name: 'System Administrator',
        status: 'active',
        must_change_password: true,
        mfa_enabled: false,
        roles: [role],
      });
      await this.userRepo.save(created);
      await this.markInitialized();
      this.logger.warn(`Bootstrap admin user created: "${rootLogin}". Change password after first login.`);
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
      this.logger.warn(`Bootstrap admin user updated: "${rootLogin}"`);
    } else {
      this.logger.log(`Bootstrap admin user already exists: "${rootLogin}"`);
    }

    await this.markInitialized();
  }

  private async markInitialized(): Promise<void> {
    const key = 'system.initialized';
    const existing = await this.settingRepo.findOne({ where: { key } });
    if (!existing) {
      await this.settingRepo.save({ key, value: 'true' });
    }
  }

  private async seedDefaultRoles(): Promise<void> {
    const defaultRoles: { name: string; permissions: string[] }[] = [
      { name: 'super_admin', permissions: ['*'] },
      { name: 'admin', permissions: ['*'] },
      {
        name: 'operator',
        permissions: [
          'users.read',
          'schedules.read', 'schedules.write', 'schedules.publish',
          'devices.read', 'devices.write',
          'content.read', 'content.write',
          'audit.read',
        ],
      },
      {
        name: 'viewer',
        permissions: [
          'users.read',
          'schedules.read',
          'devices.read',
          'content.read',
          'audit.read',
        ],
      },
    ];

    for (const def of defaultRoles) {
      const exists = await this.roleRepo.findOne({ where: { name: def.name } });
      if (!exists) {
        await this.roleRepo.save(this.roleRepo.create(def));
        this.logger.log(`Seeded default role "${def.name}"`);
      }
    }
  }

  private parseBoolean(value: string | undefined, defaultValue: boolean): boolean {
    if (value === undefined) return defaultValue;
    const normalized = value.trim().toLowerCase();
    if (['1', 'true', 'yes', 'on'].includes(normalized)) return true;
    if (['0', 'false', 'no', 'off'].includes(normalized)) return false;
    return defaultValue;
  }
}
