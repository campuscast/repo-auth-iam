import { Injectable, BadRequestException, NotFoundException, ForbiddenException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Role } from './role.entity';
import { User } from '../users/user.entity';
import { AuditClient } from '@campuscast/shared-libs';

const SYSTEM_PERMISSIONS = [
  'users.read', 'users.write',
  'schedules.read', 'schedules.write', 'schedules.publish',
  'devices.read', 'devices.write',
  'content.read', 'content.write',
  'audit.read',
  'zones.read', 'zones.write',
] as const;

@Injectable()
export class RolesService {
  private readonly auditClient: AuditClient;

  constructor(
    @InjectRepository(Role) private readonly roleRepo: Repository<Role>,
    @InjectRepository(User) private readonly userRepo: Repository<User>,
  ) {
    this.auditClient = new AuditClient();
  }

  async list() {
    const roles = await this.roleRepo.find({ order: { name: 'ASC' } });
    return {
      data: roles.map(r => this.toDto(r)),
      available_permissions: [...SYSTEM_PERMISSIONS],
    };
  }

  async getById(id: string) {
    const role = await this.roleRepo.findOne({ where: { id } });
    if (!role) throw new NotFoundException('Role not found');
    return this.toDto(role);
  }

  async create(dto: { name: string; permissions: string[] }, actorId: string) {
    if (!dto.name?.trim()) throw new BadRequestException('Name is required');

    const existing = await this.roleRepo.findOne({ where: { name: dto.name.trim() } });
    if (existing) throw new BadRequestException('Role with this name already exists');

    const role = this.roleRepo.create({
      name: dto.name.trim(),
      permissions: dto.permissions || [],
    });
    const saved = await this.roleRepo.save(role);

    this.auditClient.append({
      event_type: 'iam.role_created',
      actor_type: 'user',
      actor_id: actorId,
      resource_type: 'role',
      resource_id: saved.id,
      action: 'create',
      detail: { name: saved.name, permissions: saved.permissions },
    });

    return this.toDto(saved);
  }

  async update(id: string, dto: { name?: string; permissions?: string[] }, actorId: string) {
    const role = await this.roleRepo.findOne({ where: { id } });
    if (!role) throw new NotFoundException('Role not found');

    // Protect system roles from renaming
    if (dto.name && ['super_admin', 'admin'].includes(role.name) && dto.name !== role.name) {
      throw new ForbiddenException('Cannot rename system roles');
    }

    if (dto.name !== undefined) {
      const trimmed = dto.name.trim();
      if (trimmed !== role.name) {
        const dup = await this.roleRepo.findOne({ where: { name: trimmed } });
        if (dup) throw new BadRequestException('Role name already in use');
        role.name = trimmed;
      }
    }

    if (dto.permissions !== undefined) {
      role.permissions = dto.permissions;
    }

    const saved = await this.roleRepo.save(role);

    this.auditClient.append({
      event_type: 'iam.role_updated',
      actor_type: 'user',
      actor_id: actorId,
      resource_type: 'role',
      resource_id: id,
      action: 'update',
      detail: { changes: dto },
    });

    return this.toDto(saved);
  }

  async assignRoleToUser(userId: string, roleId: string, actorId: string) {
    const user = await this.userRepo.findOne({ where: { id: userId }, relations: ['roles'] });
    if (!user) throw new NotFoundException('User not found');

    const role = await this.roleRepo.findOne({ where: { id: roleId } });
    if (!role) throw new NotFoundException('Role not found');

    const alreadyHas = user.roles.some(r => r.id === roleId);
    if (alreadyHas) return { message: 'Role already assigned' };

    user.roles = [...user.roles, role];
    await this.userRepo.save(user);

    this.auditClient.append({
      event_type: 'iam.role_assigned',
      actor_type: 'user',
      actor_id: actorId,
      resource_type: 'user',
      resource_id: userId,
      action: 'assign_role',
      detail: { role_id: roleId, role_name: role.name },
    });

    return { message: 'Role assigned', roles: user.roles.map(r => ({ id: r.id, name: r.name })) };
  }

  async removeRoleFromUser(userId: string, roleId: string, actorId: string) {
    const user = await this.userRepo.findOne({ where: { id: userId }, relations: ['roles'] });
    if (!user) throw new NotFoundException('User not found');

    const role = await this.roleRepo.findOne({ where: { id: roleId } });
    if (!role) throw new NotFoundException('Role not found');

    // Prevent removing admin role if it would leave zero admins
    if (['admin', 'super_admin'].includes(role.name)) {
      const activeAdminCount = await this.userRepo
        .createQueryBuilder('user')
        .innerJoin('user.roles', 'role')
        .where('role.name IN (:...roles)', { roles: ['admin', 'super_admin'] })
        .andWhere('user.status = :status', { status: 'active' })
        .getCount();

      if (activeAdminCount <= 1) {
        throw new ForbiddenException('Cannot remove admin role from the last admin user');
      }
    }

    user.roles = user.roles.filter(r => r.id !== roleId);
    await this.userRepo.save(user);

    this.auditClient.append({
      event_type: 'iam.role_removed',
      actor_type: 'user',
      actor_id: actorId,
      resource_type: 'user',
      resource_id: userId,
      action: 'remove_role',
      detail: { role_id: roleId, role_name: role.name },
    });

    return { message: 'Role removed', roles: user.roles.map(r => ({ id: r.id, name: r.name })) };
  }

  private toDto(role: Role) {
    return {
      id: role.id,
      name: role.name,
      permissions: role.permissions || [],
    };
  }
}
