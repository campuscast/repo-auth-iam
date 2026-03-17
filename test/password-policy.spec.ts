import { BadRequestException } from '@nestjs/common';
import { assertPasswordPolicy, validatePasswordPolicy } from '../src/auth/password-policy';

describe('Password policy', () => {
  it('accepts a strong password', () => {
    expect(validatePasswordPolicy('StrongPass123!')).toEqual([]);
    expect(() => assertPasswordPolicy('StrongPass123!')).not.toThrow();
  });

  it('returns all required issues for weak password', () => {
    const issues = validatePasswordPolicy('weak');
    expect(issues).toEqual(
      expect.arrayContaining([
        expect.stringContaining('at least'),
        expect.stringContaining('uppercase'),
        expect.stringContaining('digit'),
        expect.stringContaining('special'),
      ]),
    );
  });

  it('throws BadRequestException when assertion fails', () => {
    expect(() => assertPasswordPolicy('PasswordOnly')).toThrow(BadRequestException);
  });
});
