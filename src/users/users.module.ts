import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { User } from './user.entity';
import { Role } from '../roles/role.entity';
import { UserZoneAssignment } from './user-zone-assignment.entity';
import { UsersService } from './users.service';
import { UsersController } from './users.controller';
import { PasswordController } from './password.controller';

@Module({
  imports: [TypeOrmModule.forFeature([User, Role, UserZoneAssignment])],
  providers: [UsersService],
  controllers: [UsersController, PasswordController],
  exports: [TypeOrmModule, UsersService],
})
export class UsersModule {}
