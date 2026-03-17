import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { TypeOrmModule } from '@nestjs/typeorm';
import { User } from '../users/user.entity';
import { UserZoneAssignment } from '../users/user-zone-assignment.entity';
import { Role } from '../roles/role.entity';
import { SystemSetting } from '../system/system-setting.entity';
import { BootstrapRootUserService } from './bootstrap-root-user.service';

@Module({
  imports: [TypeOrmModule.forFeature([User, UserZoneAssignment, Role, SystemSetting])],
  providers: [AuthService, BootstrapRootUserService],
  controllers: [AuthController],
  exports: [AuthService],
})
export class AuthModule {}
