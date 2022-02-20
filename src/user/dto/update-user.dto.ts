import { IsString, IsEmail, IsOptional } from 'class-validator';
import { UserRoles } from '../user-roles.enum';
export class UpdateUserDto {
  @IsOptional()
  @IsString({
    message: 'Informe um nome de usuário válido',
  })
  name: string;

  @IsOptional()
  @IsEmail(
    {},
    {
      message: 'Informe um endereço de email válido',
    },
  )
  email: string;

  @IsOptional()
  role: UserRoles;

  @IsOptional()
  status: boolean;
}
