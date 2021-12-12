import { Controller, Get, Post, Request, UseGuards } from '@nestjs/common';
import { AppService } from './app.service';
import { AuthService } from './auth/auth.service';
import { JwtAuthGuard } from './auth/guards/jwt-auth.guard';
import { LocalAuthGuard } from './auth/guards/local-auth.guard';
import { Public } from './auth/public.decorator';

@Controller()
export class AppController {
  constructor(
    private readonly appService: AppService,
    private readonly authService: AuthService,
  ) {}

  @Public()
  @UseGuards(LocalAuthGuard)
  @Post('auth/login')
  async login(@Request() req) {
    return this.authService.login(req.user);
  }

  @UseGuards(JwtAuthGuard)
  @Get('profile')
  getProfile(@Request() req) {
    return req.user;
  }

  @Public()
  @Get('ping')
  findAll() {
    return 'pong';
  }

  @Public()
  @Post('auth/google/verify')
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
