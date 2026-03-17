import { BadRequestException } from '@nestjs/common';
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
});
