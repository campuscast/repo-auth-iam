import 'reflect-metadata';
import * as bcrypt from 'bcrypt';
import { DataSource } from 'typeorm';
import { User } from '../users/user.entity';
import { Role } from '../roles/role.entity';
import { UserZoneAssignment } from '../users/user-zone-assignment.entity';
import { SystemSetting } from '../system/system-setting.entity';
import { Init1700000000000 } from '../migrations/1700000000000-Init';
import { IamExtensions1700000000001 } from '../migrations/1700000000001-IamExtensions';
import { validatePasswordPolicy, MIN_PASSWORD_LENGTH } from '../auth/password-policy';

const dataSource = new DataSource({
  type: 'postgres',
  url:
    process.env.DATABASE_URL ||
    'postgresql://campuscast:campuscast@localhost:5432/auth_db',
  entities: [User, Role, UserZoneAssignment, SystemSetting],
  migrations: [Init1700000000000, IamExtensions1700000000001],
});

function parseBoolean(value: string | undefined, defaultValue: boolean): boolean {
  if (value === undefined) return defaultValue;
  const normalized = value.trim().toLowerCase();
  if (['1', 'true', 'yes', 'on'].includes(normalized)) return true;
  if (['0', 'false', 'no', 'off'].includes(normalized)) return false;
  return defaultValue;
}

function requireEnv(name: string): string {
  const value = process.env[name]?.trim();
  if (!value) {
    throw new Error(`Missing required environment variable: ${name}`);
  }
  return value;
}

async function seedDefaultRoles(roleRepo: ReturnType<DataSource['getRepository']>) {
  const defaults = [
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
        'users.read', 'schedules.read', 'devices.read',
        'content.read', 'audit.read',
      ],
    },
  ];

  for (const def of defaults) {
    const exists = await roleRepo.findOne({ where: { name: def.name } });
    if (!exists) {
      await roleRepo.save(roleRepo.create(def));
      console.log(`[bootstrap-admin] Seeded role "${def.name}"`);
    }
  }
}

async function main() {
  const adminEmail = requireEnv('AUTH_BOOTSTRAP_ADMIN_EMAIL');
  const adminPassword = requireEnv('AUTH_BOOTSTRAP_ADMIN_PASSWORD');
  const adminRole = (process.env.AUTH_BOOTSTRAP_ADMIN_ROLE || 'admin').trim();
  const resetPassword = parseBoolean(
    process.env.AUTH_BOOTSTRAP_ADMIN_RESET_PASSWORD,
    false,
  );

  if (!adminRole) {
    throw new Error('AUTH_BOOTSTRAP_ADMIN_ROLE must be non-empty');
  }

  if (adminEmail === 'root' && adminPassword === 'admin') {
    throw new Error('Insecure credentials root/admin are not allowed for admin bootstrap');
  }

  const passwordPolicyIssues = validatePasswordPolicy(adminPassword);
  if (passwordPolicyIssues.length > 0) {
    throw new Error(
      `Password policy violation for AUTH_BOOTSTRAP_ADMIN_PASSWORD (min length ${MIN_PASSWORD_LENGTH}, uppercase, lowercase, digit, special character required): ` +
        passwordPolicyIssues.join('; '),
    );
  }

  await dataSource.initialize();
  await dataSource.runMigrations();

  const userRepo = dataSource.getRepository(User);
  const roleRepo = dataSource.getRepository(Role);
  const settingRepo = dataSource.getRepository(SystemSetting);

  // Seed default roles
  await seedDefaultRoles(roleRepo);

  let role = await roleRepo.findOne({ where: { name: adminRole } });
  if (!role) {
    role = roleRepo.create({ name: adminRole, permissions: ['*'] });
    role = await roleRepo.save(role);
    console.log(`[bootstrap-admin] Created role "${adminRole}"`);
  }

  // Check init state
  const initSetting = await settingRepo.findOne({ where: { key: 'system.initialized' } });

  const user = await userRepo.findOne({
    where: { email: adminEmail },
    relations: ['roles'],
  });

  const existingAdminsCount = await userRepo
    .createQueryBuilder('user')
    .innerJoin('user.roles', 'role')
    .where('role.name = :roleName', { roleName: adminRole })
    .getCount();

  if (!user) {
    if (initSetting?.value === 'true' && existingAdminsCount > 0) {
      throw new Error(
        `Refusing bootstrap: system is already initialized and role "${adminRole}" is already assigned. ` +
          'Duplicate super-admin bootstrap is blocked.',
      );
    }

    const passwordHash = await bcrypt.hash(adminPassword, 10);
    const created = userRepo.create({
      email: adminEmail,
      password_hash: passwordHash,
      name: 'System Administrator',
      status: 'active',
      must_change_password: true,
      mfa_enabled: false,
      roles: [role],
    });
    await userRepo.save(created);

    // Mark system as initialized
    if (!initSetting) {
      await settingRepo.save({ key: 'system.initialized', value: 'true' });
    }

    console.log(`[bootstrap-admin] Created first administrator "${adminEmail}"`);
    return;
  }

  const hasRole = (user.roles || []).some((assignedRole) => assignedRole.name === adminRole);
  if (!hasRole && existingAdminsCount > 0) {
    throw new Error(
      `Refusing bootstrap: role "${adminRole}" already assigned to another user. ` +
        'Duplicate super-admin bootstrap is blocked.',
    );
  }

  let changed = false;
  if (!hasRole) {
    user.roles = [...(user.roles || []), role];
    changed = true;
  }

  if (resetPassword) {
    user.password_hash = await bcrypt.hash(adminPassword, 10);
    user.must_change_password = true;
    changed = true;
  }

  if (changed) {
    await userRepo.save(user);
    console.log(`[bootstrap-admin] Updated administrator "${adminEmail}"`);
  } else {
    console.log(`[bootstrap-admin] Administrator "${adminEmail}" already bootstrapped`);
  }

  // Ensure initialized flag
  if (!initSetting) {
    await settingRepo.save({ key: 'system.initialized', value: 'true' });
  }
}

main()
  .catch((error) => {
    console.error(`[bootstrap-admin] ${error instanceof Error ? error.message : String(error)}`);
    process.exitCode = 1;
  })
  .finally(async () => {
    if (dataSource.isInitialized) {
      await dataSource.destroy();
    }
  });
