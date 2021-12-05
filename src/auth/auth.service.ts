import { Injectable, UnauthorizedException } from '@nestjs/common';
import { UsersService } from 'src/users/users.service';
import { JwtService } from '@nestjs/jwt';
import { OAuth2Client } from 'google-auth-library';
import { ConfigService } from '@nestjs/config';
import { config } from 'process';

@Injectable()
export class AuthService {
  constructor(
    private readonly usersService: UsersService,
    private readonly jwtService: JwtService,
    private readonly googleAuthClient: OAuth2Client,
    private readonly configService: ConfigService,
  ) {}

  async validateUser(username: string, pass: string): Promise<any> {
    const user = await this.usersService.findOne(username);
    if (user && user.password === pass) {
      const { password, ...result } = user;
      return result;
    }
    return null;
  }

  async login(user: any) {
    const payload = { username: user.username, sub: user.id };
    return {
      access_token: this.jwtService.sign(payload),
    };
  }

  async validadeGoogleToken(token: string) {
    const ticket = await this.googleAuthClient.verifyIdToken({
      idToken: token,
      audience: this.configService.get('OAUTH_GOOGLE_ID'),
    });
    const { email, name, sub } = ticket.getPayload();

    if (this.verifyEmail(email)) {
      return {
        access_token: this.jwtService.sign({
          email,
          name,
          sub,
        }),
      };
    } else {
      // throw unauthorized error
      throw new UnauthorizedException('Unauthorized');
    }
  }

  verifyEmail(email: string) {
    return ['israel.schmitt.j@gmail.com'].includes(email);
  }
}
