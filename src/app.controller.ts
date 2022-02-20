import { Controller, Get, Request, UseGuards } from '@nestjs/common';
import { JwtAuthGuard } from './auth/guards/jwt-auth.guard';
import { Public } from 'src/common/decorators/public.decorator';

@Controller()
export class AppController {
  @UseGuards(JwtAuthGuard)
  @Get('profile')
  getProfile(@Request() req) {
    return req.user;
  }

  @Public()
  @Get('ping')
  ping() {
    return 'pong';
  }

  @Public()
  @Get('/')
  root() {
    return 'Welcome to the auth API';
  }
}
