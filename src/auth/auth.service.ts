import { Injectable, UnauthorizedException } from '@nestjs/common';
import { UsersService } from 'src/users/users.service';
import { JwtService } from '@nestjs/jwt';
import { OAuth2Client } from 'google-auth-library';
import { ConfigService } from '@nestjs/config';
import { createPublicKey, createHash } from 'crypto';
import * as jwk from 'rsa-pem-to-jwk';

@Injectable()
export class AuthService {
  private key: any = '';
  private kid: any = '';
  private privateKey = '';

  constructor(
    private readonly usersService: UsersService,
    private readonly jwtService: JwtService,
    private readonly googleAuthClient: OAuth2Client,
    private readonly configService: ConfigService,
  ) {
    this.privateKey = configService.get('jwt.privateKey');

    this.key = createPublicKey({
      key: this.privateKey,
      type: 'pkcs1',
      format: 'pem',
    }).export({ type: 'spki', format: 'der' });

    this.kid = createHash('md5')
      .update(this.key)
      .digest('hex')
      .match(/.{2}/g)
      .join(':');
  }

  async validateUser(username: string, pass: string): Promise<any> {
    const user = await this.usersService.findOne(username);
    if (user && user.password === pass) {
      const { password, ...result } = user;
      return result;
    }
    return null;
  }

  async login(user: any) {
    return {
      access_token: this.signJwt(user.username, user.username, user.id),
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
        access_token: this.signJwt(email, name, sub),
      };
    } else {
      // throw unauthorized error
      throw new UnauthorizedException('Unauthorized');
    }
  }

  signJwt(userName: string, name: string, userId: string) {
    const payload = {
      userName: userName,
      name: name,
      sub: userId,
      keyid: this.kid,
    };

    return this.jwtService.sign(payload);
  }

  getJWKS() {
    const feed = (string: string) => string.trim() + '\n';

    const jwks = jwk(
      feed(this.privateKey),
      { kid: this.kid, use: 'sig' },
      'public',
    );

    return { keys: [jwks] };
  }

  verifyEmail(email: string) {
    return ['israel.schmitt.j@gmail.com'].includes(email);
  }
}
