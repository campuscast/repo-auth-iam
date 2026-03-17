import { Injectable, CanActivate, ExecutionContext, ForbiddenException } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { PERMISSIONS_KEY } from './require-permissions.decorator';

@Injectable()
export class PermissionsGuard implements CanActivate {
  constructor(private readonly reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const required = this.reflector.getAllAndOverride<string[]>(PERMISSIONS_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);

    if (!required || required.length === 0) return true;

    const request = context.switchToHttp().getRequest<{
      user?: { roles?: string[]; permissions?: string[] };
    }>();
    const userPerms = request.user?.permissions || [];
    const userRoles = request.user?.roles || [];

    // Wildcard permission grants all access
    if (userPerms.includes('*')) return true;

    // super_admin and admin roles have implicit full access
    if (userRoles.includes('super_admin') || userRoles.includes('admin')) return true;

    const hasAll = required.every(p => userPerms.includes(p));
    if (!hasAll) {
      throw new ForbiddenException(`Missing required permissions: ${required.join(', ')}`);
    }

    return true;
  }
}
