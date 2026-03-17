import 'reflect-metadata';
import * as bcrypt from 'bcrypt';
import { DataSource } from 'typeorm';
import { User } from '../users/user.entity';
import { Role } from '../roles/role.entity';
import { UserZoneAssignment } from '../users/user-zone-assignment.entity';
import { Init1700000000000 } from '../migrations/1700000000000-Init';

const dataSource = new DataSource({
  type: 'postgres',
  url:
    process.env.DATABASE_URL ||
    'postgresql://campuscast:campuscast@localhost:5432/auth_db',
  entities: [User, Role, UserZoneAssignment],
  migrations: [Init1700000000000],
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

  await dataSource.initialize();
  await dataSource.runMigrations();

  const userRepo = dataSource.getRepository(User);
  const roleRepo = dataSource.getRepository(Role);

  let role = await roleRepo.findOne({ where: { name: adminRole } });
  if (!role) {
    role = roleRepo.create({ name: adminRole, permissions: ['*'] });
    role = await roleRepo.save(role);
    console.log(`[bootstrap-admin] Created role "${adminRole}"`);
  }

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
    if (existingAdminsCount > 0) {
      throw new Error(
        `Refusing bootstrap: role "${adminRole}" already assigned to another user. ` +
          'Duplicate super-admin bootstrap is blocked.',
      );
    }

    const passwordHash = await bcrypt.hash(adminPassword, 10);
    const created = userRepo.create({
      email: adminEmail,
      password_hash: passwordHash,
      mfa_enabled: false,
      roles: [role],
    });
    await userRepo.save(created);
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
    changed = true;
  }

  if (changed) {
    await userRepo.save(user);
    console.log(`[bootstrap-admin] Updated administrator "${adminEmail}"`);
    return;
  }

  console.log(`[bootstrap-admin] Administrator "${adminEmail}" already bootstrapped`);
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
