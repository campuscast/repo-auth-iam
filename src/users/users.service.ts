import { Injectable, BadRequestException, NotFoundException, ForbiddenException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, ILike } from 'typeorm';
import * as bcrypt from 'bcrypt';
import { User } from './user.entity';
import { Role } from '../roles/role.entity';
import { UserZoneAssignment } from './user-zone-assignment.entity';
import { AuditClient } from '@campuscast/shared-libs';
import { assertPasswordPolicy } from '../auth/password-policy';

export interface CreateUserDto {
  email: string;
  name?: string;
  password: string;
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
  private readonly auditClient: AuditClient;

  constructor(
    @InjectRepository(User) private readonly userRepo: Repository<User>,
    @InjectRepository(Role) private readonly roleRepo: Repository<Role>,
    @InjectRepository(UserZoneAssignment) private readonly uzaRepo: Repository<UserZoneAssignment>,
  ) {
    this.auditClient = new AuditClient();
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

    return {
      data: users.map(u => this.toDto(u)),
      pagination: { total, page: params.page, page_size: params.page_size },
    };
  }

  async getById(id: string) {
    const user = await this.userRepo.findOne({ where: { id }, relations: ['roles'] });
    if (!user) throw new NotFoundException('User not found');

    const zones = await this.uzaRepo.find({ where: { user_id: id } });

    return {
      ...this.toDto(user),
      zones: zones.map(z => ({ zone_id: z.zone_id, role: z.role })),
    };
  }

  async create(dto: CreateUserDto, actorId: string) {
    if (!dto.email?.trim()) throw new BadRequestException('Email is required');
    assertPasswordPolicy(dto.password, 'Password');

    const existing = await this.userRepo.findOne({ where: { email: dto.email.trim() } });
    if (existing) throw new BadRequestException('User with this email already exists');

    const password_hash = await bcrypt.hash(dto.password, 10);

    let roles: Role[] = [];
    if (dto.role_ids?.length) {
      roles = await this.roleRepo.findByIds(dto.role_ids);
      if (roles.length !== dto.role_ids.length) {
        throw new BadRequestException('One or more role IDs are invalid');
      }
    }

    const user = this.userRepo.create({
      email: dto.email.trim(),
      name: dto.name?.trim() || undefined,
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

    return this.toDto(saved);
  }

  async update(id: string, dto: UpdateUserDto, actorId: string) {
    const user = await this.userRepo.findOne({ where: { id }, relations: ['roles'] });
    if (!user) throw new NotFoundException('User not found');

    if (dto.email !== undefined) {
      const trimmed = dto.email.trim();
      if (trimmed !== user.email) {
        const dup = await this.userRepo.findOne({ where: { email: trimmed } });
        if (dup) throw new BadRequestException('Email already in use');
        user.email = trimmed;
      }
    }

    if (dto.name !== undefined) {
      user.name = dto.name.trim() || '';
    }

    if (dto.status !== undefined) {
      if (!['active', 'inactive'].includes(dto.status)) {
        throw new BadRequestException('Status must be "active" or "inactive"');
      }
      if (dto.status === 'inactive') {
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

    return this.toDto(saved);
  }

  async deactivate(id: string, actorId: string) {
    const user = await this.userRepo.findOne({ where: { id }, relations: ['roles'] });
    if (!user) throw new NotFoundException('User not found');
    if (user.status === 'inactive') return this.toDto(user);

    await this.ensureNotLastAdmin(user);

    user.status = 'inactive';
    const saved = await this.userRepo.save(user);

    this.auditClient.append({
      event_type: 'iam.user_deactivated',
      actor_type: 'user',
      actor_id: actorId,
      resource_type: 'user',
      resource_id: id,
      action: 'deactivate',
      detail: { email: user.email },
    });

    return this.toDto(saved);
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

  private toDto(user: User) {
    return {
      id: user.id,
      email: user.email,
      name: user.name || user.email,
      status: user.status,
      must_change_password: user.must_change_password,
      roles: (user.roles || []).map(r => ({ id: r.id, name: r.name })),
      created_at: user.created_at?.toISOString(),
      updated_at: user.updated_at?.toISOString(),
    };
  }
}
