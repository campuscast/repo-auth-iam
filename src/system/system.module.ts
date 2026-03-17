import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { SystemSetting } from './system-setting.entity';
import { SystemService } from './system.service';
import { SystemController } from './system.controller';
import { User } from '../users/user.entity';

@Module({
  imports: [TypeOrmModule.forFeature([SystemSetting, User])],
  providers: [SystemService],
  controllers: [SystemController],
  exports: [SystemService],
})
export class SystemModule {}
