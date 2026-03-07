import { Module } from '@nestjs/common';
import { MetricsModule } from '@campuscast/shared-libs';
import { ConfigModule } from '@nestjs/config';
import { TypeOrmModule } from '@nestjs/typeorm';
import { AuthModule } from './auth/auth.module';
import { UsersModule } from './users/users.module';
import { RolesModule } from './roles/roles.module';
import { DeviceAuthModule } from './device-auth/device-auth.module';
import { User } from './users/user.entity';
import { Role } from './roles/role.entity';
import { UserZoneAssignment } from './users/user-zone-assignment.entity';
import { HealthController } from './common/health.controller';
import { appConfig, dbConfig, redisConfig, validate } from './config';

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
      entities: [User, Role, UserZoneAssignment],
      synchronize: process.env.NODE_ENV === 'development',
      logging: process.env.NODE_ENV === 'development',
    }),
    AuthModule,
    UsersModule,
    RolesModule,
    DeviceAuthModule,
      MetricsModule,
  ],
  controllers: [HealthController],
})
export class AppModule {}
