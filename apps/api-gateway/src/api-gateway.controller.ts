import { Controller, Get, Inject } from '@nestjs/common';
import { ClientProxy } from '@nestjs/microservices';
import { lastValueFrom, timeout, catchError, throwError } from 'rxjs';

@Controller()
export class ApiGatewayController {
  constructor(
    @Inject('AUTH_SERVICE') private readonly authClient: ClientProxy,
  ) {}

  @Get('/')
  async root() {
    const obs$ = this.authClient
      .send(
        { cmd: 'get_auth' },
        { via: 'gateway', at: new Date().toISOString() },
      )
      .pipe(
        timeout(2000),
        catchError((err) =>
          throwError(
            () => new Error(`Auth service error: ${err?.message || err}`),
          ),
        ),
      );

    const response = await lastValueFrom(obs$);
    return response;
  }

  @Get('/health')
  health() {
    return { ok: true, service: 'api-gateway', mode: 'HTTP' };
  }
}
