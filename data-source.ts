import { DataSource } from 'typeorm';
import { User } from './src/users/user.entity';
import { Role } from './src/roles/role.entity';
import { UserZoneAssignment } from './src/users/user-zone-assignment.entity';
import { Init1700000000000 } from './src/migrations/1700000000000-Init';

export default new DataSource({
  type: 'postgres',
  url:
    process.env.DATABASE_URL ||
    'postgresql://campuscast:campuscast@localhost:5432/auth_db',
  entities: [User, Role, UserZoneAssignment],
  migrations: [Init1700000000000],
});
