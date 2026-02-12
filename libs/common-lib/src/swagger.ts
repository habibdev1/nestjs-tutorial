import { INestApplication } from '@nestjs/common';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import { writeFileSync, mkdirSync, existsSync } from 'fs';
import { join } from 'path';

/**
 * Shared Swagger setup for all apps.
 *
 * @param app - The Nest application.
 * @param opts - Title/description/version and routePrefix for docs UI.
 */
export function setupSwagger(
  app: INestApplication,
  opts: {
    title: string;
    description: string;
    version?: string;
    routePrefix?: string; // default: 'docs'
    addBearerAuth?: boolean; // default: true
  },
) {
  const routePrefix = opts.routePrefix ?? 'docs';
  const addBearer = opts.addBearerAuth ?? true;

  // const isProd = process.env.NODE_ENV === 'production';
  // const baseUrl = isProd
  //   ? 'https://nestjs-tutorial.darmist.com/backend'
  //   : 'http://localhost:3501';

  const builder = new DocumentBuilder()
    .setTitle(opts.title)
    .setDescription(opts.description)
    .setVersion(opts.version ?? '1.0.0')
    .addServer('https://aero.darmist.com/backend', 'Production Server')
    .addServer('http://localhost:3501', 'Local Development');
  // .addServer(baseUrl, isProd ? 'Production Server' : 'Local Development');

  // JWT Bearer (access token)
  if (addBearer) {
    builder.addBearerAuth(
      {
        type: 'http',
        scheme: 'bearer',
        bearerFormat: 'JWT',
        name: 'Authorization',
        description:
          'Use a valid **access token**.\n\nFormat: `Bearer <ACCESS_TOKEN>`',
        in: 'header',
      },
      'bearer',
    );
  }

  // You can add global servers if needed, e.g. local dev
  // builder.addServer('http://localhost:3501', 'Local (Gateway)');

  const config = builder.build();

  const document = SwaggerModule.createDocument(app, config, {
    // You can whitelist modules or extra models here if needed
    // include: [],
    // deepScanRoutes: true,
  });

  SwaggerModule.setup(routePrefix, app, document, {
    jsonDocumentUrl: `${routePrefix}/json`,
    explorer: true,
    customSiteTitle: `${opts.title} — API Docs`,
  });

  // Export OpenAPI JSON to /openapi folder at the app root
  try {
    const outDir = join(process.cwd(), 'openapi');
    if (!existsSync(outDir)) mkdirSync(outDir, { recursive: true });
    const file = join(outDir, `${kebab(opts.title)}.json`);
    writeFileSync(file, JSON.stringify(document, null, 2));

    console.log(`🧾 OpenAPI exported: ${file}`);
  } catch (e) {
    console.warn('OpenAPI export failed:', (e as Error).message);
  }

  console.log(`📘 Swagger UI: /${routePrefix}  (json: /${routePrefix}/json)`);
}

function kebab(name: string) {
  return (name || 'api')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/(^-|-$)/g, '');
}
