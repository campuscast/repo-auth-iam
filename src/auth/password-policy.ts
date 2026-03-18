import { BadRequestException } from '@nestjs/common';

const MIN_PASSWORD_LENGTH = 8;

function collectPasswordPolicyIssues(password: string): string[] {
  const issues: string[] = [];

  if (password.length < MIN_PASSWORD_LENGTH) {
    issues.push(`be at least ${MIN_PASSWORD_LENGTH} characters long`);
  }

  return issues;
}

export function assertPasswordPolicy(password: string, fieldName = 'Password') {
  const normalized = String(password || '');
  const issues = collectPasswordPolicyIssues(normalized);
  if (!issues.length) {
    return;
  }

  throw new BadRequestException(`${fieldName} must ${issues.join(', ')}`);
}

export function validatePasswordPolicy(password: string): string[] {
  return collectPasswordPolicyIssues(String(password || ''));
}

export { MIN_PASSWORD_LENGTH };
