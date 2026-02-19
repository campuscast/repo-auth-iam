import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { TypeOrmModule } from '@nestjs/typeorm';
import { User } from '../users/user.entity';
import { UserZoneAssignment } from '../users/user-zone-assignment.entity';
@Module({
  imports: [TypeOrmModule.forFeature([User, UserZoneAssignment])],
  providers: [AuthService],
  controllers: [AuthController],
  exports: [AuthService],
})
export class AuthModule {}
