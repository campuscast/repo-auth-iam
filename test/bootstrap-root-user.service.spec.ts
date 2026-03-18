import { Test } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { BootstrapRootUserService } from '../src/auth/bootstrap-root-user.service';
import { User } from '../src/users/user.entity';
import { Role } from '../src/roles/role.entity';
import { SystemSetting } from '../src/system/system-setting.entity';

describe('BootstrapRootUserService', () => {
  const originalEnv = { ...process.env };

  let service: BootstrapRootUserService;
  let userRepo: any;
  let roleRepo: any;
  let settingRepo: any;

  beforeEach(async () => {
    process.env = {
      ...originalEnv,
      AUTH_BOOTSTRAP_ROOT_ENABLED: 'true',
      AUTH_BOOTSTRAP_ROOT_EMAIL: 'root@example.local',
      AUTH_BOOTSTRAP_ROOT_PASSWORD: 'StrongPwd123!',
      AUTH_BOOTSTRAP_ROOT_ROLE: 'admin',
    };

    userRepo = {
      findOne: jest.fn(),
      save: jest.fn(),
      create: jest.fn((data: any) => data),
    };

    roleRepo = {
      findOne: jest.fn(async ({ where }: { where: { name: string } }) => {
        const name = where?.name;
        if (!name) return null;
        return { id: `${name}-id`, name, permissions: ['*'] };
      }),
      save: jest.fn(async (value: any) => value),
      create: jest.fn((data: any) => data),
    };

    settingRepo = {
      findOne: jest.fn(),
      save: jest.fn(async (value: any) => value),
    };

    const module = await Test.createTestingModule({
      providers: [
        BootstrapRootUserService,
        { provide: getRepositoryToken(User), useValue: userRepo },
        { provide: getRepositoryToken(Role), useValue: roleRepo },
        { provide: getRepositoryToken(SystemSetting), useValue: settingRepo },
      ],
    }).compile();

    service = module.get(BootstrapRootUserService);
  });

  afterEach(() => {
    process.env = { ...originalEnv };
    jest.restoreAllMocks();
    jest.clearAllMocks();
  });

  it('marks system initialized=true even if setting already exists with false', async () => {
    userRepo.findOne.mockResolvedValue({
      id: 'user-1',
      email: 'root@example.local',
      roles: [{ id: 'admin-id', name: 'admin', permissions: ['*'] }],
    });
    settingRepo.findOne
      .mockResolvedValueOnce({ key: 'system.initialized', value: 'false' })
      .mockResolvedValueOnce({ key: 'system.initialized', value: 'false' });

    await service.onApplicationBootstrap();

    expect(settingRepo.save).toHaveBeenCalledWith(
      expect.objectContaining({ key: 'system.initialized', value: 'true' }),
    );
  });

  it('skips creating bootstrap user when system is already initialized', async () => {
    userRepo.findOne.mockResolvedValue(null);
    settingRepo.findOne.mockResolvedValue({ key: 'system.initialized', value: 'true' });

    await service.onApplicationBootstrap();

    expect(userRepo.save).not.toHaveBeenCalled();
  });
});
