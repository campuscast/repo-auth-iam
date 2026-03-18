import { buildOtpAuthUri, generateTotpCode, generateTotpSecret, verifyTotpCode } from '../src/auth/totp.util';

describe('TOTP utility', () => {
  it('generates a verifiable TOTP code', () => {
    const secret = generateTotpSecret();
    const timestampMs = 1_710_000_000_000;
    const code = generateTotpCode(secret, { timestampMs });
    expect(code).toMatch(/^\d{6}$/);
    expect(verifyTotpCode(secret, code, { timestampMs, window: 0 })).toBe(true);
    expect(verifyTotpCode(secret, code, { timestampMs: timestampMs + 180_000, window: 0 })).toBe(false);
  });

  it('builds otpauth uri', () => {
    const uri = buildOtpAuthUri({
      issuer: 'CampusCast',
      accountName: 'admin@campuscast.local',
      secret: 'JBSWY3DPEHPK3PXP',
    });
    expect(uri.startsWith('otpauth://totp/')).toBe(true);
    expect(uri).toContain('issuer=CampusCast');
    expect(uri).toContain('secret=JBSWY3DPEHPK3PXP');
  });
});
