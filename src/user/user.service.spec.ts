import { Test, TestingModule } from '@nestjs/testing';
import { User } from '@prisma/client';
import { PrismaService } from 'src/prisma.service';
import { UserService } from './user.service';

const date = new Date();

const userArray: User[] = [
  {
    id: 'ckzvsh78g0004wzuag1jr4x60',
    name: 'John Doe',
    email: 'john@doe.com.br',
    role: 'ADMIN',
    status: true,
    salt: '$2b$10$IiJwRrMHYLL7UYCaK32KHO',
    confirmationToken:
      'c93ddee1daf7b26981353c0954bb7d7eee9c9e208c1f38779a18a8f4001c6078',
    password: '$2b$10$IiJwRrMHYLL7UYCaK32KHOaGPKn4R1/exlvkPxpUwVCiKnn40Dwvm',
    recoveryToken: '',
    createdAt: date,
    updatedAt: date,
  },
  {
    id: 'cl078l3nb000009ju5lcvf4a2',
    name: 'John cloe',
    email: 'john@cloe.com.br',
    role: 'ADMIN',
    status: true,
    salt: '$2b$10$IiJwRrMHYLL7UYCaK32KHO',
    confirmationToken:
      'c93ddee1daf7b26981353c0954bb7d7eee9c9e208c1f38779a18a8f4001c6078',
    password: '$2b$10$IiJwRrMHYLL7UYCaK32KHOaGPKn4R1/exlvkPxpUwVCiKnn40Dwvm',
    recoveryToken: '',
    createdAt: date,
    updatedAt: date,
  },
];

const user: User = userArray[0];

const db = {
  user: {
    findMany: jest.fn().mockResolvedValue(userArray),
    findOne: jest.fn().mockResolvedValue(user),
    create: jest.fn().mockResolvedValue(user),
    update: jest.fn().mockResolvedValue(user),
    delete: jest.fn().mockResolvedValue(user),
  },
};

describe('UserService', () => {
  let service: UserService;
  let prisma: PrismaService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [UserService, { provide: PrismaService, useValue: db }],
    }).compile();

    service = module.get<UserService>(UserService);
    prisma = module.get<PrismaService>(PrismaService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('users', () => {
    it('should return an array of users', async () => {
      const users = await service.users({});
      expect(users).toEqual(userArray);
    });
  });

  describe('user', () => {
    it('should get a single user', () => {
      expect(
        service.user({ id: 'ckzvsh78g0004wzuag1jr4x60' }),
      ).resolves.toEqual(user);
    });
  });

  describe('insertOne', () => {
    it('should successfully insert a user', () => {
      expect(
        service.createUser({
          id: 'ckzvsh78g0004wzuag1jr4x60',
          name: 'John Doe',
          email: 'john@doe.com.br',
          role: 'ADMIN',
          status: true,
          salt: '$2b$10$IiJwRrMHYLL7UYCaK32KHO',
          confirmationToken:
            'c93ddee1daf7b26981353c0954bb7d7eee9c9e208c1f38779a18a8f4001c6078',
          password:
            '$2b$10$IiJwRrMHYLL7UYCaK32KHOaGPKn4R1/exlvkPxpUwVCiKnn40Dwvm',
          recoveryToken: '',
          createdAt: date,
          updatedAt: date,
        }),
      ).resolves.toEqual(user);
    });
  });

  describe('updateOne', () => {
    it('should call the update method', async () => {
      const cat = await service.updateUser({
        where: { id: 'ckzvsh78g0004wzuag1jr4x60' },
        data: {
          name: 'John Doe',
          email: 'john@doe.com.br',
          role: 'ADMIN',
          status: true,
          salt: '$2b$10$IiJwRrMHYLL7UYCaK32KHO',
          confirmationToken:
            'c93ddee1daf7b26981353c0954bb7d7eee9c9e208c1f38779a18a8f4001c6078',
          password:
            '$2b$10$IiJwRrMHYLL7UYCaK32KHOaGPKn4R1/exlvkPxpUwVCiKnn40Dwvm',
          recoveryToken: '',
          createdAt: date,
          updatedAt: date,
        },
      });
      expect(cat).toEqual(user);
    });
  });

  describe('deleteOne', () => {
    it('should return {deleted: true}', () => {
      expect(
        service.deleteUser({ id: 'ckzvsh78g0004wzuag1jr4x60' }),
      ).resolves.toEqual({ deleted: true });
    });
  });

  it('should return {deleted: false, message: err.message}', () => {
    expect(service.deleteUser({ id: 'doihnasodsaod' })).resolves.toEqual({
      deleted: false,
      message: 'Bad Delete Method.',
    });
  });
});
