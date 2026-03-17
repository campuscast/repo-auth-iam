import { ExecutionContext, ForbiddenException } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { PermissionsGuard } from '../src/common/permissions.guard';

function createMockContext(user?: { roles?: string[]; permissions?: string[] }): ExecutionContext {
  return {
    switchToHttp: () => ({
      getRequest: () => ({ user }),
    }),
    getHandler: () => jest.fn(),
    getClass: () => jest.fn(),
  } as any;
}

describe('PermissionsGuard', () => {
  let guard: PermissionsGuard;
  let reflector: Reflector;

  beforeEach(() => {
    reflector = new Reflector();
    guard = new PermissionsGuard(reflector);
  });

  it('should allow when no permissions are required', () => {
    jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(undefined);
    const ctx = createMockContext({ roles: [], permissions: [] });
    expect(guard.canActivate(ctx)).toBe(true);
  });

  it('should allow when user has wildcard permission', () => {
    jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(['users.write']);
    const ctx = createMockContext({ roles: [], permissions: ['*'] });
    expect(guard.canActivate(ctx)).toBe(true);
  });

  it('should allow when user has admin role', () => {
    jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(['users.write']);
    const ctx = createMockContext({ roles: ['admin'], permissions: [] });
    expect(guard.canActivate(ctx)).toBe(true);
  });

  it('should allow when user has super_admin role', () => {
    jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(['users.write']);
    const ctx = createMockContext({ roles: ['super_admin'], permissions: [] });
    expect(guard.canActivate(ctx)).toBe(true);
  });

  it('should allow when user has exact required permissions', () => {
    jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(['users.read']);
    const ctx = createMockContext({ roles: ['viewer'], permissions: ['users.read', 'audit.read'] });
    expect(guard.canActivate(ctx)).toBe(true);
  });

  it('should deny when user lacks required permissions', () => {
    jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(['users.write']);
    const ctx = createMockContext({ roles: ['viewer'], permissions: ['users.read'] });
    expect(() => guard.canActivate(ctx)).toThrow(ForbiddenException);
  });

  it('should deny when user has no permissions at all', () => {
    jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(['users.read']);
    const ctx = createMockContext({ roles: [], permissions: [] });
    expect(() => guard.canActivate(ctx)).toThrow(ForbiddenException);
  });

  it('should require ALL listed permissions', () => {
    jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(['users.read', 'users.write']);
    const ctx = createMockContext({ roles: ['operator'], permissions: ['users.read'] });
    expect(() => guard.canActivate(ctx)).toThrow(ForbiddenException);
  });
});
