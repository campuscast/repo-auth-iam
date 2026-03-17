import { Injectable, Logger } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { SystemSetting } from './system-setting.entity';
import { User } from '../users/user.entity';

const INIT_KEY = 'system.initialized';
const INIT_VALUE = 'true';

@Injectable()
export class SystemService {
  private readonly logger = new Logger(SystemService.name);

  constructor(
    @InjectRepository(SystemSetting) private readonly settingRepo: Repository<SystemSetting>,
    @InjectRepository(User) private readonly userRepo: Repository<User>,
  ) {}

  async getInitState(): Promise<{
    initialized: boolean;
    has_admin: boolean;
    admin_count: number;
  }> {
    const setting = await this.settingRepo.findOne({ where: { key: INIT_KEY } });
    const adminCount = await this.userRepo
      .createQueryBuilder('user')
      .innerJoin('user.roles', 'role')
      .where('role.name IN (:...roles)', { roles: ['admin', 'super_admin'] })
      .andWhere('user.status = :status', { status: 'active' })
      .getCount();

    return {
      initialized: setting?.value === INIT_VALUE,
      has_admin: adminCount > 0,
      admin_count: adminCount,
    };
  }

  async markInitialized(): Promise<void> {
    const existing = await this.settingRepo.findOne({ where: { key: INIT_KEY } });
    if (existing) {
      existing.value = INIT_VALUE;
      await this.settingRepo.save(existing);
    } else {
      await this.settingRepo.save({ key: INIT_KEY, value: INIT_VALUE });
    }
    this.logger.log('System marked as initialized');
  }

  async isInitialized(): Promise<boolean> {
    const setting = await this.settingRepo.findOne({ where: { key: INIT_KEY } });
    return setting?.value === INIT_VALUE;
  }
}
