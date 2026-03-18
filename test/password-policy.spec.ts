import { BadRequestException } from '@nestjs/common';
import { assertPasswordPolicy, validatePasswordPolicy } from '../src/auth/password-policy';

describe('Password policy', () => {
  it('accepts an 8-char password', () => {
    expect(validatePasswordPolicy('12345678')).toEqual([]);
    expect(() => assertPasswordPolicy('12345678')).not.toThrow();
  });

  it('returns min-length issue for short password', () => {
    const issues = validatePasswordPolicy('weak');
    expect(issues).toEqual(expect.arrayContaining([expect.stringContaining('at least')]));
  });

  it('throws BadRequestException when assertion fails', () => {
    expect(() => assertPasswordPolicy('short')).toThrow(BadRequestException);
  });
});
