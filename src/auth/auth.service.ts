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
    };

    return this.jwtService.sign(payload, {
      keyid: this.kid,
      issuer: 'auth',
      audience: 'api',
    });
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

  getOpenIdConfiguration() {
    const config = {
      issuer: 'http://52.40.167.82:5000/',
      authorization_endpoint: 'http://52.40.167.82:5000/',
      jwks_uri: 'http://52.40.167.82:5000/.well-known/jwks.json',
      device_authorization_endpoint: 'http://52.40.167.82:5000/',
      token_endpoint: 'http://52.40.167.82:5000/',
      userinfo_endpoint: 'http://52.40.167.82:5000/',
      revocation_endpoint: 'http://52.40.167.82:5000/',
      id_token_signing_alg_values_supported: ['RS256'],
      subject_types_supported: ['public'],
      response_types_supported: [
        'access_token',
        'code',
        'token',
        'id_token',
        'code token',
        'code id_token',
        'token id_token',
        'code token id_token',
        'none',
      ],
    };

    return config;
  }

  verifyEmail(email: string) {
    return ['israel.schmitt.j@gmail.com'].includes(email);
  }
}
