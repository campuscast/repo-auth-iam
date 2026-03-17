import { Module } from '@nestjs/common';
import { MetricsModule } from '@campuscast/shared-libs';
import { ConfigModule } from '@nestjs/config';
import { TypeOrmModule } from '@nestjs/typeorm';
import { AuthModule } from './auth/auth.module';
import { UsersModule } from './users/users.module';
import { RolesModule } from './roles/roles.module';
import { DeviceAuthModule } from './device-auth/device-auth.module';
import { SystemModule } from './system/system.module';
import { User } from './users/user.entity';
import { Role } from './roles/role.entity';
import { UserZoneAssignment } from './users/user-zone-assignment.entity';
import { SystemSetting } from './system/system-setting.entity';
import { Init1700000000000 } from './migrations/1700000000000-Init';
import { IamExtensions1700000000001 } from './migrations/1700000000001-IamExtensions';
import { HealthController } from './common/health.controller';
import { appConfig, dbConfig, redisConfig, validate } from './config';

const dbSynchronize = process.env.DB_SYNCHRONIZE === 'true';
const dbMigrationsRun = process.env.DB_MIGRATIONS_RUN !== 'false';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      load: [appConfig, dbConfig, redisConfig],
      validate,
    }),
    TypeOrmModule.forRoot({
      type: 'postgres',
      url: process.env.DATABASE_URL || 'postgresql://campuscast:campuscast@localhost:5432/auth_db',
      entities: [User, Role, UserZoneAssignment, SystemSetting],
      migrations: [Init1700000000000, IamExtensions1700000000001],
      migrationsRun: dbMigrationsRun,
      synchronize: dbSynchronize,
      logging: process.env.NODE_ENV === 'development',
    }),
    AuthModule,
    UsersModule,
    RolesModule,
    DeviceAuthModule,
    SystemModule,
    MetricsModule,
  ],
  controllers: [HealthController],
})
export class AppModule {}
