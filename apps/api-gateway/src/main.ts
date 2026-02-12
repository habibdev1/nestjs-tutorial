import { NestFactory } from '@nestjs/core';
import { Logger } from '@nestjs/common';
import * as path from 'node:path';
import { ApiGatewayModule } from './api-gateway.module';
import { setupSwagger } from '@app/common-lib';

// Dynamically infer service name from directory name
const serviceName = path.basename(path.dirname(__filename)) || 'service';

async function bootstrap() {
  const ENV_PREFIX = serviceName.toUpperCase().replace(/-/g, '_');
  const httpPort = Number(process.env[`${ENV_PREFIX}_HTTP_PORT`]) || 3000;

  // Create HTTP app
  const app = await NestFactory.create(ApiGatewayModule);

  // // Attach TCP microservice
  // app.connectMicroservice<MicroserviceOptions>({
  //   transport: Transport.TCP,
  //   options: { host: '0.0.0.0', port: tcpPort },
  // });

  // Swagger only in non-production
  if (process.env.NODE_ENV !== 'production') {
    setupSwagger(app, {
      title: 'API Gateway',
      description: 'Public HTTP entrypoint routing to microservices (TCP).',
      version: '1.0.0',
      routePrefix: 'docs', // → http://localhost:3501/docs
      addBearerAuth: true,
    });
  }

  await app.startAllMicroservices();
  await app.listen(httpPort);

  const logger = new Logger(serviceName);
  logger.log(
    `\n🚀  ${serviceName} ready!\n` +
      `    REST: http://localhost:${httpPort}\n` +
      `    ENV : ${process.env.NODE_ENV}`,
  );
}
bootstrap();
