import { Controller, Get, Post, Request, UseGuards } from '@nestjs/common';
import { AuthService } from './auth.service';
import { LocalAuthGuard } from './guards/local-auth.guard';
import { Public } from './public.decorator';

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
  async register(@Request() req) {
    return await this.authService.signUp(req.body);
  }

  @Public()
  @Post('/google/verify')
  async googleVerify(@Request() req) {
    return await this.authService.validadeGoogleToken(req.body.tokenId);
  }

  @Public()
  @Get('.well-known/jwks.json')
  getJWKS() {
    console.log('getJWKS');
    return this.authService.getJWKS();
  }

  @Public()
  @Get('.well-known/openid-configuration')
  getOpenIdConfiguration() {
    return this.authService.getOpenIdConfiguration();
  }
}
