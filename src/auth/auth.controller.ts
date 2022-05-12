import {
  Body,
  Controller,
  Get,
  Post,
  Request,
  UseGuards,
  ValidationPipe,
} from '@nestjs/common';
import { CreateUserDto } from 'src/user/dto/create-user.dto';
import { AuthService } from './auth.service';
import { LocalAuthGuard } from './guards/local-auth.guard';
import { Public } from '../common/decorators/public.decorator';
import { Role } from 'src/common/decorators/role.decorator';
import { UserRoles } from 'src/user/user-roles.enum';
import { RolesGuard } from './guards/roles.guard';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Public()
  @UseGuards(LocalAuthGuard)
  @Post('/login')
  async login(@Request() req) {
    return this.authService.login(req.user);
  }

  @Public()
  @Post('/register')
  async register(@Body(ValidationPipe) createUserDto: CreateUserDto) {
    return await this.authService.signUp(createUserDto, UserRoles.USER);
  }

  @Public()
  @Post('/google/verify')
  async googleVerify(@Request() req) {
    return await this.authService.validadeGoogleToken(req.body.tokenId);
  }

  @Post('/register/admin')
  @Role(UserRoles.ADMIN)
  @UseGuards(RolesGuard)
  async createAdminUser(@Body(ValidationPipe) createUserDto: CreateUserDto) {
    return await this.authService.signUp(createUserDto, UserRoles.ADMIN);
  }

  @Public()
  @Get('.well-known/jwks.json')
  getJWKS() {
    return this.authService.getJWKS();
  }

  @Public()
  @Get('.well-known/openid-configuration')
  getOpenIdConfiguration() {
    return this.authService.getOpenIdConfiguration();
  }
}
