import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import * as helmet from 'helmet';
import { WinstonModule } from 'nest-winston';
import { winstonConfig } from './config/winston.config';
import config from './config/configuration';

async function bootstrap() {
  const logger = WinstonModule.createLogger(winstonConfig);
  const app = await NestFactory.create(AppModule, { logger });
  app.enableCors({ ...config().cors, credentials: true });
  app.use(helmet());
  await app.listen(5000);
}
bootstrap();
