import { Test } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { BadRequestException, NotFoundException, ForbiddenException } from '@nestjs/common';
import { UsersService } from '../src/users/users.service';
import { User } from '../src/users/user.entity';
import { Role } from '../src/roles/role.entity';
import { UserZoneAssignment } from '../src/users/user-zone-assignment.entity';

// Mock AuditClient
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
  name: 'Test User',
  password_hash: '$2b$10$hashedpassword',
  status: 'active',
  must_change_password: false,
  mfa_enabled: false,
  mfa_secret: null,
  roles: [],
  created_at: new Date('2025-01-01'),
  updated_at: new Date('2025-01-01'),
  ...overrides,
} as User);

describe('UsersService', () => {
  let service: UsersService;
  let userRepo: any;
  let roleRepo: any;
  let uzaRepo: any;

  beforeEach(async () => {
    const qb = {
      leftJoinAndSelect: jest.fn().mockReturnThis(),
      andWhere: jest.fn().mockReturnThis(),
      orderBy: jest.fn().mockReturnThis(),
      skip: jest.fn().mockReturnThis(),
      take: jest.fn().mockReturnThis(),
      getManyAndCount: jest.fn().mockResolvedValue([[], 0]),
      innerJoin: jest.fn().mockReturnThis(),
      where: jest.fn().mockReturnThis(),
      getCount: jest.fn().mockResolvedValue(0),
    };

    userRepo = {
      findOne: jest.fn(),
      findByIds: jest.fn(),
      create: jest.fn((data: any) => ({ ...mockUser(), ...data })),
      save: jest.fn((user: any) => Promise.resolve({ ...mockUser(), ...user })),
      createQueryBuilder: jest.fn(() => qb),
    };

    roleRepo = {
      findOne: jest.fn(),
      findByIds: jest.fn().mockResolvedValue([]),
    };

    uzaRepo = {
      find: jest.fn().mockResolvedValue([]),
      save: jest.fn(),
      create: jest.fn((data: any) => data),
      delete: jest.fn(),
    };

    const module = await Test.createTestingModule({
      providers: [
        UsersService,
        { provide: getRepositoryToken(User), useValue: userRepo },
        { provide: getRepositoryToken(Role), useValue: roleRepo },
        { provide: getRepositoryToken(UserZoneAssignment), useValue: uzaRepo },
      ],
    }).compile();

    service = module.get(UsersService);
  });

  describe('create', () => {
    it('should create a user with valid data', async () => {
      userRepo.findOne.mockResolvedValue(null); // no duplicate
      const result = await service.create(
        { email: 'new@test.com', password: 'Password123!' },
        'actor-1',
      );
      expect(result.email).toBe('new@test.com');
      expect(result.status).toBe('active');
      expect(userRepo.save).toHaveBeenCalled();
    });

    it('should reject empty email', async () => {
      await expect(
        service.create({ email: '', password: 'Password123!' }, 'actor-1'),
      ).rejects.toThrow(BadRequestException);
    });

    it('should reject short password', async () => {
      await expect(
        service.create({ email: 'a@b.com', password: 'short' }, 'actor-1'),
      ).rejects.toThrow(BadRequestException);
    });

    it('should reject duplicate email', async () => {
      userRepo.findOne.mockResolvedValue(mockUser());
      await expect(
        service.create({ email: 'test@example.com', password: 'Password123!' }, 'actor-1'),
      ).rejects.toThrow(BadRequestException);
    });

    it('should reject invalid role IDs', async () => {
      userRepo.findOne.mockResolvedValue(null);
      roleRepo.findByIds.mockResolvedValue([mockRole()]);
      await expect(
        service.create(
          { email: 'a@b.com', password: 'Password123!', role_ids: ['role-1', 'bad-id'] },
          'actor-1',
        ),
      ).rejects.toThrow(BadRequestException);
    });

    it('should assign roles when valid role_ids provided', async () => {
      userRepo.findOne.mockResolvedValue(null);
      const role = mockRole();
      roleRepo.findByIds.mockResolvedValue([role]);
      const result = await service.create({ email: 'a@b.com', password: 'Password123!', role_ids: ['role-1'] }, 'actor-1');
      expect(userRepo.create).toHaveBeenCalledWith(
        expect.objectContaining({ roles: [role] }),
      );
    });
  });

  describe('getById', () => {
    it('should return user DTO when found', async () => {
      userRepo.findOne.mockResolvedValue(mockUser({ roles: [mockRole()] }));
      const result = await service.getById('user-1');
      expect(result.id).toBe('user-1');
      expect(result.roles).toHaveLength(1);
    });

    it('should throw NotFoundException when user not found', async () => {
      userRepo.findOne.mockResolvedValue(null);
      await expect(service.getById('missing')).rejects.toThrow(NotFoundException);
    });
  });

  describe('update', () => {
    it('should update user name', async () => {
      userRepo.findOne.mockResolvedValue(mockUser({ roles: [] }));
      const result = await service.update('user-1', { name: 'New Name' }, 'actor-1');
      expect(result.name).toBe('New Name');
    });

    it('should throw NotFoundException for missing user', async () => {
      userRepo.findOne.mockResolvedValue(null);
      await expect(
        service.update('missing', { name: 'x' }, 'actor-1'),
      ).rejects.toThrow(NotFoundException);
    });

    it('should reject duplicate email on update', async () => {
      userRepo.findOne
        .mockResolvedValueOnce(mockUser()) // find target
        .mockResolvedValueOnce(mockUser({ id: 'other', email: 'dup@test.com' })); // dup check
      await expect(
        service.update('user-1', { email: 'dup@test.com' }, 'actor-1'),
      ).rejects.toThrow(BadRequestException);
    });

    it('should reject invalid status', async () => {
      userRepo.findOne.mockResolvedValue(mockUser({ roles: [] }));
      await expect(
        service.update('user-1', { status: 'banned' }, 'actor-1'),
      ).rejects.toThrow(BadRequestException);
    });
  });

  describe('deactivate', () => {
    it('should deactivate a non-admin user', async () => {
      userRepo.findOne.mockResolvedValue(mockUser({ roles: [mockRole()] }));
      const result = await service.deactivate('user-1', 'actor-1');
      expect(result.status).toBe('inactive');
    });

    it('should throw ForbiddenException when deactivating last admin', async () => {
      const adminRole = mockRole({ name: 'admin', permissions: ['*'] });
      userRepo.findOne.mockResolvedValue(mockUser({ roles: [adminRole] }));
      // qb.getCount returns 1 (last admin)
      const qb = userRepo.createQueryBuilder();
      qb.getCount.mockResolvedValue(1);
      await expect(
        service.deactivate('user-1', 'actor-1'),
      ).rejects.toThrow(ForbiddenException);
    });

    it('should return existing DTO if already inactive', async () => {
      userRepo.findOne.mockResolvedValue(mockUser({ status: 'inactive' }));
      const result = await service.deactivate('user-1', 'actor-1');
      expect(result.status).toBe('inactive');
      expect(userRepo.save).not.toHaveBeenCalled();
    });
  });
});
