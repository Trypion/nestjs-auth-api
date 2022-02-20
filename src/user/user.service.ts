import { Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma.service';
import { User, Prisma } from '@prisma/client';

@Injectable()
export class UserService {
  constructor(private readonly prisma: PrismaService) {}

  async user(UserWhereInput: Prisma.UserWhereInput): Promise<User> {
    return this.prisma.user.findFirst({
      where: UserWhereInput,
    });
  }

  async users(params: {
    skip?: number;
    take?: number;
    where?: Prisma.UserWhereInput;
    orderBy?: Prisma.UserOrderByWithRelationInput;
    cursor?: Prisma.UserWhereUniqueInput;
  }): Promise<User[]> {
    const { where, orderBy, cursor, skip, take } = params;
    return this.prisma.user.findMany({
      where,
      orderBy,
      cursor,
      skip,
      take,
    });
  }

  async userInfo(
    UserWhereInput: Prisma.UserWhereInput,
  ): Promise<Prisma.UserSelect> {
    const select: Prisma.UserSelect = {
      id: true,
      email: true,
      name: true,
      role: true,
    };

    return this.prisma.user.findFirst({ where: UserWhereInput, select });
  }

  async createUser(data: Prisma.UserCreateInput): Promise<User> {
    return this.prisma.user.create({ data });
  }

  async updateUser(params: {
    where: Prisma.UserWhereUniqueInput;
    data: Prisma.UserUpdateInput;
  }): Promise<User> {
    const { where, data } = params;
    return this.prisma.user.update({ where, data });
  }

  async deleteUser(where: Prisma.UserWhereUniqueInput): Promise<User> {
    return this.prisma.user.delete({ where });
  }
}
