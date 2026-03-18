import { BadRequestException, ForbiddenException } from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import { PasswordController } from '../src/users/password.controller';

jest.mock('@campuscast/shared-libs', () => ({
  JwtAuthGuard: class JwtAuthGuard {},
  CurrentUser: () => () => undefined,
  AuditClient: jest.fn().mockImplementation(() => ({ append: jest.fn() })),
}));

describe('PasswordController', () => {
  let controller: PasswordController;
  let userRepo: { findOne: jest.Mock; save: jest.Mock };

  beforeEach(() => {
    userRepo = {
      findOne: jest.fn(),
      save: jest.fn(),
    };
    controller = new PasswordController(userRepo as any);
  });

  it('rejects weak new password on self password change', async () => {
    await expect(
      controller.changeOwnPassword(
        { current_password: 'CurrentPass123!', new_password: 'weak' },
        { sub: 'user-1' },
      ),
    ).rejects.toThrow(BadRequestException);

    expect(userRepo.findOne).not.toHaveBeenCalled();
  });

  it('rejects weak temporary password on admin reset path', async () => {
    userRepo.findOne.mockResolvedValue({
      id: 'user-1',
      email: 'user@test.local',
      password_hash: '$2b$10$hashed',
      must_change_password: false,
    });

    await expect(
      controller.adminResetPassword(
        'user-1',
        { temporary_password: 'weak' },
        { sub: 'admin-1' },
      ),
    ).rejects.toThrow(BadRequestException);
  });

  it('allows password change without current_password when user must change password', async () => {
    userRepo.findOne.mockResolvedValue({
      id: 'user-1',
      email: 'user@test.local',
      password_hash: await bcrypt.hash('TempPass12', 10),
      must_change_password: true,
    });
    userRepo.save.mockImplementation(async (user) => user);

    await expect(
      controller.changeOwnPassword(
        { new_password: 'NewPass12' },
        { sub: 'user-1' },
      ),
    ).resolves.toEqual(expect.objectContaining({ ok: true }));
  });

  it('requires current_password for normal password change flow', async () => {
    userRepo.findOne.mockResolvedValue({
      id: 'user-1',
      email: 'user@test.local',
      password_hash: await bcrypt.hash('CurrentPass12', 10),
      must_change_password: false,
    });

    await expect(
      controller.changeOwnPassword(
        { new_password: 'NewPass12' },
        { sub: 'user-1' },
      ),
    ).rejects.toThrow(BadRequestException);
  });

  it('forbids admin reset for super_admin user', async () => {
    userRepo.findOne.mockResolvedValue({
      id: 'user-1',
      email: 'root@test.local',
      password_hash: '$2b$10$hashed',
      must_change_password: false,
      roles: [{ id: 'role-1', name: 'super_admin', permissions: ['*'] }],
    });

    await expect(
      controller.adminResetPassword(
        'user-1',
        {},
        { sub: 'admin-1' },
      ),
    ).rejects.toThrow(ForbiddenException);
  });
});
