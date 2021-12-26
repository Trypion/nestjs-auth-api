import {
  Injectable,
  UnauthorizedException,
  UnprocessableEntityException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { User } from '@prisma/client';
import * as bcrypt from 'bcrypt';
import { createHash, createPublicKey, randomBytes } from 'crypto';
import { OAuth2Client } from 'google-auth-library';
import * as jwk from 'rsa-pem-to-jwk';
import { CreateUserDto } from 'src/user/dto/create-user.dto';
import { UserRoles } from 'src/user/user-roles.enum';
import { UserService } from 'src/user/user.service';
import { CredentialsDto } from './dto/credential.dto';

@Injectable()
export class AuthService {
  private key: any;
  private kid: any;
  private privateKey: string;
  private saltRounds: number;

  constructor(
    private readonly userService: UserService,
    private readonly jwtService: JwtService,
    private readonly googleAuthClient: OAuth2Client,
    private readonly configService: ConfigService,
  ) {
    this.privateKey = configService.get('jwt.privateKey');
    this.saltRounds = configService.get('crypto.saltRounds');

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

  async signUp(createUserDto: CreateUserDto): Promise<User> {
    if (createUserDto.password != createUserDto.passwordConfirmation) {
      throw new UnprocessableEntityException('Senhas não conferem');
    } else {
      const { email, password, name } = createUserDto;

      const persistedUser = await this.userService.user({ email: email });

      if (persistedUser) {
        throw new UnprocessableEntityException('Usuário já existe');
      }

      const salt = await bcrypt.genSalt(this.saltRounds);

      const user = {
        name: name,
        email: email,
        salt: salt,
        password: await bcrypt.hash(password, salt),
        role: UserRoles.USER,
        status: true,
        confirmationToken: randomBytes(32).toString('hex'),
      };

      return this.userService.createUser(user);
    }
  }

  async login(credentialsDto: CredentialsDto): Promise<any> {
    const { email, password } = credentialsDto;
    const user = await this.userService.user({ email: email, status: true });

    if (!user) {
      throw new UnauthorizedException('Usuário não encontrado');
    }

    const hash = await bcrypt.hash(password, user.salt);

    if (hash === user.password) {
      const jwt = this.signJwt(user.email, user.name, user.id, user.role);

      return {
        user: {
          id: user.id,
          name: user.name,
          email: user.email,
          role: user.role,
          status: user.status,
        },
        token: jwt,
      };
    }
  }

  async validadeGoogleToken(token: string) {
    const ticket = await this.googleAuthClient.verifyIdToken({
      idToken: token,
      audience: this.configService.get('OAUTH_GOOGLE_ID'),
    });
    const { email, name, sub } = ticket.getPayload();

    if (this.verifyEmail(email)) {
      return {
        access_token: this.signJwt(email, name, sub, UserRoles.USER),
      };
    } else {
      // throw unauthorized error
      throw new UnauthorizedException('Unauthorized');
    }
  }

  signJwt(userName: string, name: string, userId: string, role: string) {
    const payload = {
      userName: userName,
      name: name,
      sub: userId,
      scope: role,
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
