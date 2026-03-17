import { Test } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { SystemService } from '../src/system/system.service';
import { SystemSetting } from '../src/system/system-setting.entity';
import { User } from '../src/users/user.entity';

describe('SystemService', () => {
  let service: SystemService;
  let settingRepo: any;
  let userRepo: any;

  beforeEach(async () => {
    const qb = {
      innerJoin: jest.fn().mockReturnThis(),
      where: jest.fn().mockReturnThis(),
      andWhere: jest.fn().mockReturnThis(),
      getCount: jest.fn().mockResolvedValue(0),
    };

    settingRepo = {
      findOne: jest.fn(),
      save: jest.fn((data: any) => Promise.resolve(data)),
    };

    userRepo = {
      createQueryBuilder: jest.fn(() => qb),
    };

    const module = await Test.createTestingModule({
      providers: [
        SystemService,
        { provide: getRepositoryToken(SystemSetting), useValue: settingRepo },
        { provide: getRepositoryToken(User), useValue: userRepo },
      ],
    }).compile();

    service = module.get(SystemService);
  });

  describe('getInitState', () => {
    it('should return initialized=false when no setting exists', async () => {
      settingRepo.findOne.mockResolvedValue(null);
      const result = await service.getInitState();
      expect(result.initialized).toBe(false);
      expect(result.has_admin).toBe(false);
      expect(result.admin_count).toBe(0);
    });

    it('should return initialized=true when setting exists', async () => {
      settingRepo.findOne.mockResolvedValue({ key: 'system.initialized', value: 'true' });
      const qb = userRepo.createQueryBuilder();
      qb.getCount.mockResolvedValue(2);
      const result = await service.getInitState();
      expect(result.initialized).toBe(true);
      expect(result.has_admin).toBe(true);
      expect(result.admin_count).toBe(2);
    });
  });

  describe('markInitialized', () => {
    it('should create setting when none exists', async () => {
      settingRepo.findOne.mockResolvedValue(null);
      await service.markInitialized();
      expect(settingRepo.save).toHaveBeenCalledWith(
        expect.objectContaining({ key: 'system.initialized', value: 'true' }),
      );
    });

    it('should update setting when already exists', async () => {
      const existing = { key: 'system.initialized', value: 'false' };
      settingRepo.findOne.mockResolvedValue(existing);
      await service.markInitialized();
      expect(settingRepo.save).toHaveBeenCalledWith(
        expect.objectContaining({ value: 'true' }),
      );
    });
  });

  describe('isInitialized', () => {
    it('should return false when no setting exists', async () => {
      settingRepo.findOne.mockResolvedValue(null);
      expect(await service.isInitialized()).toBe(false);
    });

    it('should return true when setting value is "true"', async () => {
      settingRepo.findOne.mockResolvedValue({ key: 'system.initialized', value: 'true' });
      expect(await service.isInitialized()).toBe(true);
    });

    it('should return false when setting value is not "true"', async () => {
      settingRepo.findOne.mockResolvedValue({ key: 'system.initialized', value: 'false' });
      expect(await service.isInitialized()).toBe(false);
    });
  });
});
