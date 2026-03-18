import { Injectable, BadRequestException, NotFoundException, ForbiddenException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { randomBytes } from 'crypto';
import * as bcrypt from 'bcrypt';
import { RedisService } from '@campuscast/shared-libs';
import { User } from './user.entity';
import { Role } from '../roles/role.entity';
import { UserZoneAssignment } from './user-zone-assignment.entity';
import { AuditClient } from '@campuscast/shared-libs';
import { assertPasswordPolicy } from '../auth/password-policy';

export interface CreateUserDto {
  email: string;
  name?: string;
  password?: string;
  role_ids?: string[];
  zone_ids?: string[];
}

export interface UpdateUserDto {
  name?: string;
  email?: string;
  status?: string;
  role_ids?: string[];
  zone_ids?: string[];
}

@Injectable()
export class UsersService {
  private static readonly MAX_LOGIN_LENGTH = 20;
  private static readonly MAX_NAME_LENGTH = 20;
  private static readonly ONLINE_KEY_PREFIX = 'auth:online:user:';
  private static readonly REVOKED_KEY_PREFIX = 'auth:revoked:user:';
  private readonly auditClient: AuditClient;

  constructor(
    @InjectRepository(User) private readonly userRepo: Repository<User>,
    @InjectRepository(Role) private readonly roleRepo: Repository<Role>,
    @InjectRepository(UserZoneAssignment) private readonly uzaRepo: Repository<UserZoneAssignment>,
    private readonly redisService: RedisService,
  ) {
    this.auditClient = new AuditClient();
  }

  private normalizeLogin(raw: string): string {
    const login = String(raw || '').trim();
    if (!login) throw new BadRequestException('Login is required');
    if (login.length > UsersService.MAX_LOGIN_LENGTH) {
      throw new BadRequestException(`Login must be at most ${UsersService.MAX_LOGIN_LENGTH} characters`);
    }
    return login;
  }

  private normalizeName(raw?: string): string | undefined {
    if (raw === undefined) return undefined;
    const name = String(raw || '').trim();
    if (!name) return '';
    if (name.length > UsersService.MAX_NAME_LENGTH) {
      throw new BadRequestException(`Name must be at most ${UsersService.MAX_NAME_LENGTH} characters`);
    }
    return name;
  }

  private generateTemporaryPassword(): string {
    return randomBytes(12).toString('base64url');
  }

  private onlineKey(userId: string): string {
    return `${UsersService.ONLINE_KEY_PREFIX}${userId}`;
  }

  private revokedKey(userId: string): string {
    return `${UsersService.REVOKED_KEY_PREFIX}${userId}`;
  }

  private async markRevoked(userId: string) {
    try {
      await this.redisService.client.set(this.revokedKey(userId), '1');
    } catch {
      // Session revocation cache is best-effort.
    }
  }

  private async clearRevoked(userId: string) {
    try {
      await this.redisService.client.del(this.revokedKey(userId));
    } catch {
      // Session revocation cache cleanup is best-effort.
    }
  }

  private async clearOnline(userId: string) {
    try {
      await this.redisService.client.del(this.onlineKey(userId));
    } catch {
      // Presence cache cleanup is best-effort.
    }
  }

  private async resolveOnlineMap(userIds: string[]): Promise<Record<string, boolean>> {
    if (!userIds.length) return {};
    try {
      const keys = userIds.map((id) => this.onlineKey(id));
      const values = await this.redisService.client.mget(keys);
      return userIds.reduce<Record<string, boolean>>((acc, id, index) => {
        acc[id] = Boolean(values[index]);
        return acc;
      }, {});
    } catch {
      return userIds.reduce<Record<string, boolean>>((acc, id) => {
        acc[id] = false;
        return acc;
      }, {});
    }
  }

  private isSuperAdminUser(user: User): boolean {
    return (user.roles || []).some((role) => role.name === 'super_admin');
  }

  private assertNotSuperAdminTarget(user: User) {
    if (this.isSuperAdminUser(user)) {
      throw new ForbiddenException('Cannot modify super_admin user via users management');
    }
  }

  async list(params: {
    page: number;
    page_size: number;
    search?: string;
    role?: string;
    status?: string;
  }) {
    const qb = this.userRepo.createQueryBuilder('user')
      .leftJoinAndSelect('user.roles', 'role');

    if (params.search) {
      qb.andWhere('(user.email ILIKE :search OR user.name ILIKE :search)', {
        search: `%${params.search}%`,
      });
    }

    if (params.role) {
      qb.andWhere('role.name = :role', { role: params.role });
    }

    if (params.status) {
      qb.andWhere('user.status = :status', { status: params.status });
    }

    qb.orderBy('user.created_at', 'DESC');
    qb.skip((params.page - 1) * params.page_size);
    qb.take(params.page_size);

    const [users, total] = await qb.getManyAndCount();
    const onlineMap = await this.resolveOnlineMap(users.map((user) => user.id));

    return {
      data: users.map((u) => this.toDto(u, u.status === 'active' && Boolean(onlineMap[u.id]))),
      pagination: { total, page: params.page, page_size: params.page_size },
    };
  }

  async getById(id: string) {
    const user = await this.userRepo.findOne({ where: { id }, relations: ['roles'] });
    if (!user) throw new NotFoundException('User not found');

    const zones = await this.uzaRepo.find({ where: { user_id: id } });
    const onlineMap = await this.resolveOnlineMap([id]);

    return {
      ...this.toDto(user, user.status === 'active' && Boolean(onlineMap[id])),
      zones: zones.map(z => ({ zone_id: z.zone_id, role: z.role })),
    };
  }

  async create(dto: CreateUserDto, actorId: string) {
    const login = this.normalizeLogin(dto.email);
    const normalizedName = this.normalizeName(dto.name);
    const temporaryPassword = dto.password ? String(dto.password) : this.generateTemporaryPassword();
    assertPasswordPolicy(temporaryPassword, 'Password');

    const existing = await this.userRepo.findOne({ where: { email: login } });
    if (existing) throw new BadRequestException('User with this email already exists');

    const password_hash = await bcrypt.hash(temporaryPassword, 10);

    let roles: Role[] = [];
    if (dto.role_ids?.length) {
      roles = await this.roleRepo.findByIds(dto.role_ids);
      if (roles.length !== dto.role_ids.length) {
        throw new BadRequestException('One or more role IDs are invalid');
      }
    }

    const user = this.userRepo.create({
      email: login,
      name: normalizedName || undefined,
      password_hash,
      status: 'active',
      must_change_password: true,
      roles,
    });

    const saved: User = await this.userRepo.save(user);

    if (dto.zone_ids?.length) {
      for (const zone_id of dto.zone_ids) {
        await this.uzaRepo.save(this.uzaRepo.create({
          user_id: saved.id,
          zone_id,
          role: 'editor',
        }));
      }
    }

    this.auditClient.append({
      event_type: 'iam.user_created',
      actor_type: 'user',
      actor_id: actorId,
      resource_type: 'user',
      resource_id: saved.id,
      action: 'create',
      detail: { email: saved.email, roles: roles.map(r => r.name) },
    });

    await this.clearRevoked(saved.id);
    await this.clearOnline(saved.id);

    return {
      ...this.toDto(saved, false),
      temporary_password: temporaryPassword,
    };
  }

  async update(id: string, dto: UpdateUserDto, actorId: string) {
    const user = await this.userRepo.findOne({ where: { id }, relations: ['roles'] });
    if (!user) throw new NotFoundException('User not found');
    this.assertNotSuperAdminTarget(user);
    const previousStatus = user.status;

    if (dto.email !== undefined) {
      const login = this.normalizeLogin(dto.email);
      if (login !== user.email) {
        const dup = await this.userRepo.findOne({ where: { email: login } });
        if (dup) throw new BadRequestException('Email already in use');
        user.email = login;
      }
    }

    if (dto.name !== undefined) {
      user.name = this.normalizeName(dto.name) || '';
    }

    if (dto.status !== undefined) {
      if (!['active', 'inactive'].includes(dto.status)) {
        throw new BadRequestException('Status must be "active" or "inactive"');
      }
      if (dto.status === 'inactive') {
        if (id === actorId) {
          throw new ForbiddenException('Cannot deactivate your own account');
        }
        await this.ensureNotLastAdmin(user);
      }
      user.status = dto.status;
    }

    if (dto.role_ids !== undefined) {
      const roles = await this.roleRepo.findByIds(dto.role_ids);
      if (roles.length !== dto.role_ids.length) {
        throw new BadRequestException('One or more role IDs are invalid');
      }
      user.roles = roles;
    }

    const saved = await this.userRepo.save(user);

    if (previousStatus !== saved.status) {
      if (saved.status === 'inactive') {
        await this.markRevoked(saved.id);
        await this.clearOnline(saved.id);
      } else {
        await this.clearRevoked(saved.id);
      }
    }

    if (dto.zone_ids !== undefined) {
      await this.uzaRepo.delete({ user_id: id });
      for (const zone_id of dto.zone_ids) {
        await this.uzaRepo.save(this.uzaRepo.create({
          user_id: id,
          zone_id,
          role: 'editor',
        }));
      }
    }

    this.auditClient.append({
      event_type: 'iam.user_updated',
      actor_type: 'user',
      actor_id: actorId,
      resource_type: 'user',
      resource_id: id,
      action: 'update',
      detail: { changes: dto },
    });

    const onlineMap = await this.resolveOnlineMap([saved.id]);
    return this.toDto(saved, onlineMap[saved.id] ?? false);
  }

  async deactivate(id: string, actorId: string) {
    if (id === actorId) {
      throw new ForbiddenException('Cannot deactivate your own account');
    }

    const user = await this.userRepo.findOne({ where: { id }, relations: ['roles'] });
    if (!user) throw new NotFoundException('User not found');
    this.assertNotSuperAdminTarget(user);
    if (user.status === 'inactive') {
      const onlineMap = await this.resolveOnlineMap([user.id]);
      return this.toDto(user, onlineMap[user.id] ?? false);
    }

    await this.ensureNotLastAdmin(user);

    user.status = 'inactive';
    const saved = await this.userRepo.save(user);
    await this.markRevoked(saved.id);
    await this.clearOnline(saved.id);

    this.auditClient.append({
      event_type: 'iam.user_deactivated',
      actor_type: 'user',
      actor_id: actorId,
      resource_type: 'user',
      resource_id: id,
      action: 'deactivate',
      detail: { email: user.email },
    });

    return this.toDto(saved, false);
  }

  async restore(id: string, actorId: string) {
    const user = await this.userRepo.findOne({ where: { id }, relations: ['roles'] });
    if (!user) throw new NotFoundException('User not found');
    if (user.status === 'active') {
      const onlineMap = await this.resolveOnlineMap([user.id]);
      return this.toDto(user, onlineMap[user.id] ?? false);
    }

    user.status = 'active';
    const saved = await this.userRepo.save(user);
    await this.clearRevoked(saved.id);

    this.auditClient.append({
      event_type: 'iam.user_restored',
      actor_type: 'user',
      actor_id: actorId,
      resource_type: 'user',
      resource_id: id,
      action: 'restore',
      detail: { email: user.email },
    });

    const onlineMap = await this.resolveOnlineMap([saved.id]);
    return this.toDto(saved, onlineMap[saved.id] ?? false);
  }

  async removePermanently(id: string, actorId: string) {
    if (id === actorId) {
      throw new ForbiddenException('Cannot delete your own account');
    }

    const user = await this.userRepo.findOne({ where: { id }, relations: ['roles'] });
    if (!user) throw new NotFoundException('User not found');
    this.assertNotSuperAdminTarget(user);

    if (user.status === 'active') {
      await this.ensureNotLastAdmin(user);
    }

    await this.uzaRepo.delete({ user_id: id });
    await this.userRepo.remove(user);
    await this.markRevoked(id);
    await this.clearOnline(id);

    this.auditClient.append({
      event_type: 'iam.user_deleted',
      actor_type: 'user',
      actor_id: actorId,
      resource_type: 'user',
      resource_id: id,
      action: 'delete',
      detail: { email: user.email },
    });

    return { deleted: true };
  }

  private async ensureNotLastAdmin(user: User) {
    const adminRoleNames = (user.roles || []).map(r => r.name);
    const isAdmin = adminRoleNames.some(n => n === 'admin' || n === 'super_admin');
    if (!isAdmin) return;

    const activeAdminCount = await this.userRepo
      .createQueryBuilder('user')
      .innerJoin('user.roles', 'role')
      .where('role.name IN (:...roles)', { roles: ['admin', 'super_admin'] })
      .andWhere('user.status = :status', { status: 'active' })
      .getCount();

    if (activeAdminCount <= 1) {
      throw new ForbiddenException('Cannot deactivate the last admin user');
    }
  }

  private toDto(user: User, online = false) {
    return {
      id: user.id,
      email: user.email,
      name: user.name || user.email,
      status: user.status,
      online,
      must_change_password: user.must_change_password,
      roles: (user.roles || []).map(r => ({ id: r.id, name: r.name })),
      created_at: user.created_at?.toISOString(),
      updated_at: user.updated_at?.toISOString(),
    };
  }
}
