import { Test } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { BadRequestException, NotFoundException, ForbiddenException } from '@nestjs/common';
import { RolesService } from '../src/roles/roles.service';
import { Role } from '../src/roles/role.entity';
import { User } from '../src/users/user.entity';

jest.mock('@campuscast/shared-libs', () => ({
  AuditClient: jest.fn().mockImplementation(() => ({ append: jest.fn() })),
}));

const mockRole = (overrides?: Partial<Role>): Role => ({
  id: 'role-1',
  name: 'viewer',
  permissions: ['users.read'],
  ...overrides,
} as Role);

const mockUser = (overrides?: Partial<User>): User => ({
  id: 'user-1',
  email: 'test@example.com',
  name: 'Test',
  password_hash: 'hash',
  status: 'active',
  must_change_password: false,
  mfa_enabled: false,
  mfa_secret: null,
  roles: [],
  created_at: new Date(),
  updated_at: new Date(),
  ...overrides,
} as User);

describe('RolesService', () => {
  let service: RolesService;
  let roleRepo: any;
  let userRepo: any;

  beforeEach(async () => {
    const qb = {
      innerJoin: jest.fn().mockReturnThis(),
      where: jest.fn().mockReturnThis(),
      andWhere: jest.fn().mockReturnThis(),
      getCount: jest.fn().mockResolvedValue(2),
    };

    roleRepo = {
      find: jest.fn().mockResolvedValue([]),
      findOne: jest.fn(),
      create: jest.fn((data: any) => ({ ...mockRole(), ...data })),
      save: jest.fn((role: any) => Promise.resolve({ ...mockRole(), ...role })),
    };

    userRepo = {
      findOne: jest.fn(),
      save: jest.fn((user: any) => Promise.resolve(user)),
      createQueryBuilder: jest.fn(() => qb),
    };

    const module = await Test.createTestingModule({
      providers: [
        RolesService,
        { provide: getRepositoryToken(Role), useValue: roleRepo },
        { provide: getRepositoryToken(User), useValue: userRepo },
      ],
    }).compile();

    service = module.get(RolesService);
  });

  describe('list', () => {
    it('should return roles with available_permissions', async () => {
      roleRepo.find.mockResolvedValue([mockRole()]);
      const result = await service.list();
      expect(result.data).toHaveLength(1);
      expect(result.available_permissions).toContain('users.read');
      expect(result.available_permissions).toContain('users.write');
    });
  });

  describe('create', () => {
    it('should create a role with valid data', async () => {
      roleRepo.findOne.mockResolvedValue(null);
      const result = await service.create(
        { name: 'custom', permissions: ['users.read'] },
        'actor-1',
      );
      expect(result.name).toBe('custom');
      expect(roleRepo.save).toHaveBeenCalled();
    });

    it('should reject empty name', async () => {
      await expect(
        service.create({ name: '', permissions: [] }, 'actor-1'),
      ).rejects.toThrow(BadRequestException);
    });

    it('should reject duplicate role name', async () => {
      roleRepo.findOne.mockResolvedValue(mockRole());
      await expect(
        service.create({ name: 'viewer', permissions: [] }, 'actor-1'),
      ).rejects.toThrow(BadRequestException);
    });
  });

  describe('update', () => {
    it('should update role permissions', async () => {
      roleRepo.findOne
        .mockResolvedValueOnce(mockRole({ name: 'custom' }));
      const result = await service.update('role-1', { permissions: ['users.write'] }, 'actor-1');
      expect(result.permissions).toContain('users.write');
    });

    it('should throw NotFoundException for missing role', async () => {
      roleRepo.findOne.mockResolvedValue(null);
      await expect(
        service.update('missing', { name: 'x' }, 'actor-1'),
      ).rejects.toThrow(NotFoundException);
    });

    it('should prevent renaming system roles', async () => {
      roleRepo.findOne.mockResolvedValue(mockRole({ name: 'admin' }));
      await expect(
        service.update('role-1', { name: 'renamed' }, 'actor-1'),
      ).rejects.toThrow(ForbiddenException);
    });

    it('should allow updating permissions on system roles', async () => {
      roleRepo.findOne.mockResolvedValue(mockRole({ name: 'admin', permissions: ['*'] }));
      const result = await service.update('role-1', { permissions: ['*', 'extra'] }, 'actor-1');
      expect(result.permissions).toContain('*');
    });
  });

  describe('assignRoleToUser', () => {
    it('should assign role to user', async () => {
      const user = mockUser({ roles: [] });
      const role = mockRole({ id: 'role-2', name: 'operator' });
      userRepo.findOne.mockResolvedValue(user);
      roleRepo.findOne.mockResolvedValue(role);
      const result = await service.assignRoleToUser('user-1', 'role-2', 'actor-1');
      expect(result.message).toBe('Role assigned');
      expect(userRepo.save).toHaveBeenCalled();
    });

    it('should return early if role already assigned', async () => {
      const role = mockRole({ id: 'role-2' });
      userRepo.findOne.mockResolvedValue(mockUser({ roles: [role] }));
      roleRepo.findOne.mockResolvedValue(role);
      const result = await service.assignRoleToUser('user-1', 'role-2', 'actor-1');
      expect(result.message).toBe('Role already assigned');
      expect(userRepo.save).not.toHaveBeenCalled();
    });

    it('should throw when user not found', async () => {
      userRepo.findOne.mockResolvedValue(null);
      await expect(
        service.assignRoleToUser('missing', 'role-1', 'actor-1'),
      ).rejects.toThrow(NotFoundException);
    });
  });

  describe('removeRoleFromUser', () => {
    it('should remove non-admin role', async () => {
      const role = mockRole({ id: 'role-2', name: 'viewer' });
      userRepo.findOne.mockResolvedValue(mockUser({ roles: [role] }));
      roleRepo.findOne.mockResolvedValue(role);
      const result = await service.removeRoleFromUser('user-1', 'role-2', 'actor-1');
      expect(result.message).toBe('Role removed');
    });

    it('should prevent removing admin role from last admin', async () => {
      const adminRole = mockRole({ id: 'role-a', name: 'admin' });
      userRepo.findOne.mockResolvedValue(mockUser({ roles: [adminRole] }));
      roleRepo.findOne.mockResolvedValue(adminRole);
      // Only 1 active admin
      const qb = userRepo.createQueryBuilder();
      qb.getCount.mockResolvedValue(1);
      await expect(
        service.removeRoleFromUser('user-1', 'role-a', 'actor-1'),
      ).rejects.toThrow(ForbiddenException);
    });
  });
});
