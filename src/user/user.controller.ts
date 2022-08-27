import {
  Body,
  Controller,
  ForbiddenException,
  Get,
  Param,
  Patch,
  ValidationPipe,
} from '@nestjs/common';
import { Prisma, User } from '@prisma/client';
import { GetUser } from '../common/decorators/get-user.decorator';
import { Role } from '../common/decorators/role.decorator';
import { UpdateUserDto } from './dto/update-user.dto';
import { UserRoles } from './user-roles.enum';

import { UserService } from './user.service';

@Controller('user')
export class UserController {
  constructor(private readonly userService: UserService) {}

  @Get(':id')
  @Role(UserRoles.ADMIN)
  async findUserById(@Param('id') id): Promise<Prisma.UserSelect> {
    return await this.userService.userInfo({ id });
  }

  @Patch(':id')
  @Role(UserRoles.ADMIN)
  async updateUser(
    @GetUser() user: User,
    @Body(ValidationPipe) updateUserDto: UpdateUserDto,
    @Param('id') id: string,
  ): Promise<UpdateUserDto> {
    if (user.role != UserRoles.ADMIN && user.id.toString() != id) {
      throw new ForbiddenException(
        'Você não tem autorização para acessar esse recurso',
      );
    }
    const { name, email, role, status } = await this.userService.updateUser({
      where: { id: id },
      data: updateUserDto,
    });

    return {
      name,
      email,
      role: role as UserRoles,
      status,
    };
  }
}
