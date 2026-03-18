import * as bcrypt from 'bcrypt';
import { AuthService } from '../src/auth/auth.service';
import { generateTotpCode } from '../src/auth/totp.util';

jest.mock('bcrypt', () => ({
  compare: jest.fn(),
  hash: jest.fn(),
}));

describe('AuthService MFA', () => {
  const role = { name: 'operator', permissions: ['users.read'] };
  const baseUser = {
    id: 'user-1',
    email: 'user@example.com',
    name: 'User',
    status: 'active',
    password_hash: '$2b$10$hash',
    roles: [role],
    mfa_enabled: true,
    mfa_secret: 'JBSWY3DPEHPK3PXP',
  };

  let userRepo: {
    findOne: jest.Mock;
    save: jest.Mock;
  };
  let uzaRepo: {
    find: jest.Mock;
  };
  let service: AuthService;

  beforeEach(() => {
    process.env.JWT_SECRET = 'test-jwt-secret';
    userRepo = {
      findOne: jest.fn(),
      save: jest.fn(async (value) => value),
    };
    uzaRepo = {
      find: jest.fn(async () => [{ zone_id: 'zone-a' }]),
    };
    service = new AuthService(userRepo as any, uzaRepo as any);
    (bcrypt.compare as jest.Mock).mockResolvedValue(true);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  it('returns MFA challenge on login when MFA is enabled', async () => {
    userRepo.findOne.mockResolvedValue({ ...baseUser });
    const result = await service.login(baseUser.email, 'Password123!');
    expect(result).toMatchObject({ mfa_required: true });
    expect((result as Record<string, unknown>).access_token).toBeUndefined();
  });

  it('issues token pair after MFA challenge verification', async () => {
    userRepo.findOne.mockResolvedValue({ ...baseUser });
    const loginResult = await service.login(baseUser.email, 'Password123!');
    const mfaToken = (loginResult as { mfa_token: string }).mfa_token;
    const code = generateTotpCode(baseUser.mfa_secret);

    const tokenPair = await service.verifyMfaLogin(mfaToken, code);
    expect(tokenPair.access_token).toBeTruthy();
    expect(tokenPair.refresh_token).toBeTruthy();
    expect(tokenPair.expires_in).toBeGreaterThan(0);
  });

  it('enables and disables MFA with verification code and password', async () => {
    const user = { ...baseUser, mfa_enabled: false };
    userRepo.findOne.mockResolvedValue(user);

    const code = generateTotpCode(user.mfa_secret);
    await service.enableMfa(user.id, code);
    expect(userRepo.save).toHaveBeenCalledWith(expect.objectContaining({ mfa_enabled: true }));

    user.mfa_enabled = true;
    await service.disableMfa(user.id, 'Password123!');
    expect(userRepo.save).toHaveBeenCalledWith(expect.objectContaining({ mfa_enabled: false, mfa_secret: null }));
  });
});
