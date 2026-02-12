import {
  BadRequestException,
  Body,
  Controller,
  Get,
  Headers,
  Inject,
  Post,
  Query,
  Req,
  UseGuards,
} from '@nestjs/common';
import { ClientProxy } from '@nestjs/microservices';
import { firstValueFrom, timeout, catchError, throwError } from 'rxjs';
import { SignupDto } from '../../auth-service/src/dto/signup.dto';
import { LoginDto } from '../../auth-service/src/dto/login.dto';
import { VerifyOtpDto } from '../../auth-service/src/dto/verify-otp.dto';
import { JwtAuthGuard, JwtSessionGuard, Public, Roles } from '@app/auth-lib';
import { LogoutSessionDto } from '../../auth-service/src/dto/logout-session.dto';
import { RefreshDto } from '../../auth-service/src/dto/refresh.dto';
import {
  ApiBadRequestResponse,
  ApiBearerAuth,
  ApiBody,
  ApiConflictResponse,
  ApiForbiddenResponse,
  ApiInternalServerErrorResponse,
  ApiNotFoundResponse,
  ApiOkResponse,
  ApiOperation,
  ApiQuery,
  ApiUnauthorizedResponse,
} from '@nestjs/swagger';

@Controller('gateway/auth')
export class AuthGatewayController {
  constructor(
    @Inject('AUTH_SERVICE') private readonly authClient: ClientProxy,
  ) {}

  private async sendSafe<T>(cmd: string, payload: any): Promise<T> {
    try {
      return await firstValueFrom(
        this.authClient.send<T>({ cmd }, payload).pipe(
          timeout(10000),
          catchError((error) => {
            const message =
              error?.message ||
              error?.response?.message ||
              'Auth service error';
            const errors = error?.response?.errors;
            return throwError(
              () => new BadRequestException({ message, errors }),
            );
          }),
        ),
      );
    } catch (unexpected: any) {
      throw new BadRequestException(
        unexpected?.response || {
          message: unexpected?.message || 'Auth service error',
        },
      );
    }
  }

  // ───────────────────────────────
  // Signup
  // ───────────────────────────────
  @Public()
  @Post('signup')
  @ApiOperation({
    summary: 'User Signup (Tenant-Aware Registration)',
    description: `
Registers a new user under the provided **tenant** environment.

### 🧩 Flow
1. Validates **x-tenant-id** (must be provided in header).  
2. Creates a new user with securely hashed password.  
3. Automatically sends a **welcome email** (non-blocking).  
4. Handles duplicate or validation errors gracefully.

### ⚠️ Important Notes
- The **x-tenant-id** header is mandatory to associate the user with the correct tenant.
- Duplicate username/email/mobile entries will be rejected.
- Passwords are securely hashed before storage.
`,
  })
  @ApiBody({
    description: 'User signup details',
    type: SignupDto,
    examples: {
      validExample: {
        summary: 'Example signup request',
        value: {
          name: 'John Doe',
          username: 'johndoe',
          email: 'john@example.com',
          password: 'MySecurePassword@123',
          mobile: '01712345678',
        },
      },
    },
  })
  @ApiOkResponse({
    description: 'Account successfully created under tenant',
    schema: {
      example: {
        message:
          'Your account has been created successfully. You can now log in to your AeroStitch workspace.',
        data: {
          status: 'success',
          code: 'USER_CREATED',
          data: {
            id: 'uuid',
            name: 'John Doe',
            username: 'johndoe',
            email: 'john@example.com',
            role: 'user',
          },
        },
        ts: '2025-10-11T12:30:45.123Z',
      },
    },
  })
  @ApiConflictResponse({
    description: 'Duplicate username/email/mobile detected',
    schema: {
      example: {
        message:
          'Signup failed: Some information already exists in the system. Please use different values.',
        data: {
          status: 'error',
          code: 'DUPLICATE_ENTRY',
          message: 'Duplicate fields: email "john@example.com"',
        },
        ts: '2025-10-11T12:30:45.123Z',
      },
    },
  })
  @ApiBadRequestResponse({
    description: 'Validation failed (e.g., invalid email or weak password)',
    schema: {
      example: {
        message:
          'Signup failed due to invalid or missing information. Please review your inputs.',
        data: {
          status: 'error',
          code: 'VALIDATION_FAILED',
          message: 'Password must be at least 6 characters',
        },
        ts: '2025-10-11T12:30:45.123Z',
      },
    },
  })
  @ApiInternalServerErrorResponse({
    description: 'Unexpected server error during signup',
    schema: {
      example: {
        message: 'Signup failed due to a system error. Please try again later.',
        data: {
          status: 'error',
          code: 'INTERNAL_ERROR',
          error: 'Database connection lost',
        },
        ts: '2025-10-11T12:30:45.123Z',
      },
    },
  })
  async signup(
    @Headers('x-tenant-id') tenantId: string,
    @Body() dto: SignupDto,
    @Req() req: any,
  ) {
    if (!tenantId) throw new BadRequestException('x-tenant-id is required');

    const safeReq = {
      user: req.user,
      headers: {
        'user-agent': req.headers['user-agent'] || 'unknown',
        host:
          req.headers['host'] | req.ip ||
          req.connection?.remoteAddress ||
          '0.0.0.0',
      },
    };

    const result = await this.sendSafe<any>('auth.signup', {
      ...dto,
      tenantId,
      req: safeReq,
    });
    return result;
  }

  // ───────────────────────────────
  // Login (send OTP)
  // ───────────────────────────────
  @Public()
  @Post('login')
  @ApiOperation({
    summary: 'User Login (Initiate OTP-based authentication)',
    description: `
Initiates the **OTP-based login flow** by validating credentials and sending a one-time password to the user’s registered email.

### 🧩 Flow
1. Validate tenant connection using **x-tenant-id** header.  
2. Find user by **username/email/mobile**.  
3. Verify password and account status.  
4. Generate OTP (5-minute validity).  
5. Send OTP via email.

### ⚠️ Important Notes
- This endpoint **does not log the user in immediately** — it sends an OTP for the next verification step.
- Locked or suspended users cannot proceed.
`,
  })
  @ApiBody({
    description: 'User credentials for login',
    type: LoginDto,
    examples: {
      validExample: {
        summary: 'Example login request',
        value: {
          usernameOrEmailOrMobile: 'john.doe@example.com',
          password: 'MySecurePassword@123',
        },
      },
    },
  })
  @ApiOkResponse({
    description: 'OTP successfully sent to registered email',
    schema: {
      example: {
        message:
          'A verification OTP has been sent to your registered email address. Please check your inbox.',
        data: {
          status: 'success',
          code: 'OTP_SENT',
          data: {
            loginId: 'f5b2e8c3-8f4a-4a9c-9eab-8b23d67c2337',
            channel: 'email',
            maskedEmail: 'j***@example.com',
          },
        },
        ts: '2025-10-11T12:30:45.123Z',
      },
    },
  })
  @ApiBadRequestResponse({
    description: 'Invalid tenant or missing header',
    schema: {
      example: {
        message:
          'Login failed: Tenant environment is not initialized. Please retry after selecting the correct workspace.',
        data: {
          status: 'error',
          code: 'TENANT_CONNECTION_MISSING',
          details: { tenantId: 'tenant_12345' },
        },
        ts: '2025-10-11T12:30:45.123Z',
      },
    },
  })
  @ApiUnauthorizedResponse({
    description: 'Invalid credentials, locked account, or wrong password',
    schema: {
      oneOf: [
        {
          example: {
            message:
              'Invalid credentials. Please check your username, email, or mobile number and try again.',
            data: {
              status: 'error',
              code: 'INVALID_CREDENTIALS',
              field: 'usernameOrEmailOrMobile',
            },
            ts: '2025-10-11T12:30:45.123Z',
          },
        },
        {
          example: {
            message:
              'Your account is currently locked. Please check your email for unlock instructions or contact support.',
            data: {
              status: 'error',
              code: 'ACCOUNT_LOCKED',
              email: 'john.doe@example.com',
            },
            ts: '2025-10-11T12:30:45.123Z',
          },
        },
        {
          example: {
            message:
              'Incorrect password. Please try again or reset your password if forgotten.',
            data: {
              status: 'error',
              code: 'INVALID_PASSWORD',
              field: 'password',
            },
            ts: '2025-10-11T12:30:45.123Z',
          },
        },
      ],
    },
  })
  @ApiInternalServerErrorResponse({
    description: 'System or email failure',
    schema: {
      oneOf: [
        {
          example: {
            message:
              'We could not send the OTP to your email at this moment. Please try again later.',
            data: {
              status: 'error',
              code: 'OTP_SEND_FAILED',
              error: 'SMTP connection timeout',
            },
            ts: '2025-10-11T12:30:45.123Z',
          },
        },
        {
          example: {
            message:
              'Login failed due to a system error. Please try again later.',
            data: {
              status: 'error',
              code: 'INTERNAL_ERROR',
              error: 'Database connection lost',
            },
            ts: '2025-10-11T12:30:45.123Z',
          },
        },
      ],
    },
  })
  async login(
    @Headers('x-tenant-id') tenantId: string,
    @Body() dto: LoginDto,
    @Req() req: any,
  ) {
    if (!tenantId) throw new BadRequestException('x-tenant-id is required');
    const safeReq = {
      user: req.user,
      headers: {
        'user-agent': req.headers['user-agent'] || 'unknown',
        host:
          req.headers['host'] | req.ip ||
          req.connection?.remoteAddress ||
          '0.0.0.0',
      },
    };
    const result = await this.sendSafe<any>('auth.login', {
      ...dto,
      tenantId,
      req: safeReq,
    });
    return result;
  }

  // ───────────────────────────────
  // Verify OTP → Tokens
  // ───────────────────────────────
  @Public()
  @Post('login/verify')
  @ApiOperation({
    summary: 'Verify OTP and issue JWT tokens',
    description: `
Verifies the OTP and issues **access and refresh tokens** for session-based authentication.

### 🧩 Flow
1. Validate tenant via **x-tenant-id** header.  
2. Verify the OTP against the stored reference.  
3. Issue **JWT tokens** (access & refresh).  
4. Record session information.  
5. Return tokens and user details.
`,
  })
  @ApiBody({
    description: 'OTP verification payload',
    type: VerifyOtpDto,
    examples: {
      validExample: {
        summary: 'Example request',
        value: {
          loginId: '8bfbec7f-3a2f-4d1f-a8e2-92ef1d2f3b77',
          otp: '123456',
        },
      },
    },
  })
  @ApiOkResponse({
    description: 'OTP verified and tokens issued successfully',
    schema: {
      example: {
        message: 'You have successfully logged in to AeroStitch.',
        data: {
          status: 'success',
          code: 'LOGIN_SUCCESS',
          data: {
            accessToken: 'jwt-access-token',
            refreshToken: 'jwt-refresh-token',
            sessionId: 'uuid',
            user: {
              id: 'uuid',
              username: 'johndoe',
              role: 'user',
            },
          },
        },
        ts: '2025-10-11T12:30:45.123Z',
      },
    },
  })
  @ApiUnauthorizedResponse({
    description: 'OTP invalid, expired, or mismatched',
    schema: {
      oneOf: [
        {
          example: {
            message:
              'Your OTP has expired or is invalid. Please request a new OTP to continue.',
            data: {
              status: 'error',
              code: 'OTP_EXPIRED_OR_INVALID',
              loginId: '8bfbec7f-3a2f-4d1f-a8e2-92ef1d2f3b77',
            },
            ts: '2025-10-11T12:30:45.123Z',
          },
        },
        {
          example: {
            message: 'Incorrect OTP entered. Please check and try again.',
            data: {
              status: 'error',
              code: 'INVALID_OTP',
              field: 'otp',
            },
            ts: '2025-10-11T12:30:45.123Z',
          },
        },
      ],
    },
  })
  @ApiBadRequestResponse({
    description: 'Tenant missing or invalid environment',
    schema: {
      example: {
        message:
          'OTP verification failed: Tenant environment not initialized. Please retry.',
        data: {
          status: 'error',
          code: 'TENANT_CONNECTION_MISSING',
          details: { tenantId: 'tenant_abc' },
        },
        ts: '2025-10-11T12:30:45.123Z',
      },
    },
  })
  @ApiInternalServerErrorResponse({
    description: 'Unexpected system error during OTP verification',
    schema: {
      example: {
        message:
          'Login verification failed due to an unexpected system error. Please try again later.',
        data: {
          status: 'error',
          code: 'INTERNAL_ERROR',
          error: 'Redis connection lost',
        },
        ts: '2025-10-11T12:30:45.123Z',
      },
    },
  })
  async verifyOtp(
    @Headers('x-tenant-id') tenantId: string,
    @Body() dto: VerifyOtpDto,
    @Req() req: any,
  ) {
    if (!tenantId) throw new BadRequestException('x-tenant-id is required');
    const safeReq = {
      user: req.user,
      headers: {
        'user-agent': req.headers['user-agent'] || 'unknown',
        host:
          req.headers['host'] | req.ip ||
          req.connection?.remoteAddress ||
          '0.0.0.0',
      },
    };
    const result = await this.sendSafe<any>('auth.verifyOtp', {
      ...dto,
      tenantId,
      req: safeReq,
    });
    return result;
  }

  // ───────────────────────────────
  // Unlock account
  // ───────────────────────────────
  @Public()
  @Get('unlock')
  @ApiOperation({
    summary: 'Unlock Account (via Email Token)',
    description: `
Unlocks a user account using a token received via email after too many failed login attempts.

### 🧩 Flow
1. User receives an **unlock link** through email after repeated login failures.  
2. The link contains a **token** (e.g., \`https://yourapp.com/api/auth/unlock?token=abc123\`).  
3. The token is verified in Redis; if valid, the user account is unlocked and can log in again.  
4. The unlock token is **deleted** immediately after successful verification.

### ⚠️ Notes
- The **x-tenant-id** header must always be provided.
- The token expires automatically after a set duration (e.g., 30 minutes).
- If the token is invalid, expired, or reused, an appropriate error response is returned.
`,
  })
  @ApiQuery({
    name: 'token',
    required: true,
    description: 'Unlock token from the email link',
    example: 'df81b3e2-58d4-4a55-9b70-1fbd45a9f02e',
  })
  @ApiOkResponse({
    description: 'Account unlocked successfully',
    schema: {
      example: {
        message:
          'Your account has been unlocked successfully. You may now log in again.',
        data: { userId: 'user_uuid', tenantId: 'tenant_abc' },
        meta: { status: 'success', code: 'ACCOUNT_UNLOCKED' },
        ts: '2025-10-11T12:30:45.123Z',
      },
    },
  })
  @ApiBadRequestResponse({
    description: 'Invalid, expired, or incomplete unlock token',
    schema: {
      oneOf: [
        {
          example: {
            message:
              'The unlock link is invalid or has expired. Please request a new unlock email.',
            data: null,
            meta: { status: 'error', code: 'INVALID_OR_EXPIRED_TOKEN' },
            ts: '2025-10-11T12:30:45.123Z',
          },
        },
        {
          example: {
            message:
              'Unlock request failed due to incomplete token data. Please generate a new unlock link.',
            data: null,
            meta: { status: 'error', code: 'TOKEN_DATA_INCOMPLETE' },
            ts: '2025-10-11T12:30:45.123Z',
          },
        },
      ],
    },
  })
  @ApiInternalServerErrorResponse({
    description: 'Unexpected error during unlock process',
    schema: {
      example: {
        message:
          'Account unlock failed due to a system error. Please try again later.',
        data: null,
        meta: {
          status: 'error',
          code: 'INTERNAL_ERROR',
          error: 'Redis connection lost',
        },
        ts: '2025-10-11T12:30:45.123Z',
      },
    },
  })
  async unlock(
    @Headers('x-tenant-id') tenantId: string,
    @Query('token') token: string,
    @Req() req: any,
  ) {
    if (!tenantId) throw new BadRequestException('x-tenant-id is required');
    const safeReq = {
      user: req.user,
      headers: {
        'user-agent': req.headers['user-agent'] || 'unknown',
        host:
          req.headers['host'] | req.ip ||
          req.connection?.remoteAddress ||
          '0.0.0.0',
      },
    };

    const result = await this.sendSafe<any>('auth.unlock', {
      tenantId,
      token,
      req: safeReq,
    });
    return result;
  }

  // ───────────────────────────────
  // List sessions
  // ───────────────────────────────
  @UseGuards(JwtAuthGuard, JwtSessionGuard)
  @Get('sessions')
  @ApiBearerAuth('bearer')
  @ApiOperation({
    summary: 'List Active User Sessions',
    description: `
Retrieves all **active sessions** for the currently authenticated user.

### 🧩 Flow
1. Requires a valid **JWT access token** (Bearer Auth).  
2. Identifies the user and fetches their **active sessions** from the tenant database.  
3. Returns session metadata such as device, IP, and timestamps.  

### ⚠️ Notes
- The **x-tenant-id** header must always be provided.
- Each session represents a unique login (device/browser).
- Users can have multiple active sessions concurrently.
`,
  })
  @ApiOkResponse({
    description: 'List of active sessions for the authenticated user',
    schema: {
      example: {
        message: 'Active login sessions retrieved successfully.',
        data: [
          {
            sessionId: 'c2a8d1d5-6b91-4c77-a4e0-8b5dfb4dc7a9',
            deviceName: 'Chrome on MacBook',
            ip: '192.168.1.10',
            ua: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)...',
            createdAt: '2025-09-18T12:34:56.000Z',
            lastSeen: '2025-09-18T13:00:00.000Z',
          },
          {
            sessionId: 'f87c9e32-3df2-45a4-bb2d-0a1c3c8f3f41',
            deviceName: 'iPhone Safari',
            ip: '172.20.15.23',
            ua: 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)...',
            createdAt: '2025-09-19T09:15:22.000Z',
            lastSeen: '2025-09-19T10:02:14.000Z',
          },
        ],
        meta: { status: 'success', code: 'SESSIONS_RETRIEVED' },
        ts: '2025-10-11T12:30:45.123Z',
      },
    },
  })
  @ApiBadRequestResponse({
    description: 'Missing tenant ID or invalid user context',
    schema: {
      oneOf: [
        {
          example: {
            message:
              'Unable to fetch sessions because tenant environment is not initialized.',
            data: null,
            meta: {
              status: 'error',
              code: 'TENANT_CONNECTION_MISSING',
              details: { tenantId: 'tenant_abc' },
            },
            ts: '2025-10-11T12:30:45.123Z',
          },
        },
        {
          example: {
            message:
              'Session request failed: user identity missing in the request payload.',
            data: null,
            meta: { status: 'error', code: 'USER_ID_MISSING' },
            ts: '2025-10-11T12:30:45.123Z',
          },
        },
      ],
    },
  })
  @ApiInternalServerErrorResponse({
    description: 'Unexpected error while fetching user sessions',
    schema: {
      example: {
        message:
          'Failed to retrieve sessions due to a system error. Please try again later.',
        data: null,
        meta: {
          status: 'error',
          code: 'INTERNAL_ERROR',
          error: 'Database connection lost',
        },
        ts: '2025-10-11T12:30:45.123Z',
      },
    },
  })
  async sessions(@Headers('x-tenant-id') tenantId: string, @Req() req: any) {
    if (!tenantId) throw new BadRequestException('x-tenant-id is required');
    const safeReq = {
      user: req.user,
      headers: {
        'user-agent': req.headers['user-agent'] || 'unknown',
        host:
          req.headers['host'] | req.ip ||
          req.connection?.remoteAddress ||
          '0.0.0.0',
      },
    };

    const result = await this.sendSafe<any>('auth.sessions', {
      tenantId,
      req: safeReq,
    });
    return result;
  }

  // ───────────────────────────────
  // Logout single session
  // ───────────────────────────────
  @UseGuards(JwtAuthGuard, JwtSessionGuard)
  @Post('logout/session')
  @ApiBearerAuth('bearer')
  @ApiOperation({
    summary: 'Logout a Single Active Session',
    description: `
Revokes a specific user session identified by its **sessionId**.

### 🧩 Flow
1. Requires a valid **JWT access token** (Bearer Auth).  
2. The **sessionId** (UUID) of the target session must be provided.  
3. The specified session will be removed from the user's active sessions list.  
4. A success response is returned if the session is successfully revoked.

### ⚠️ Notes
- The **x-tenant-id** header must be provided.
- If the session is already logged out or not found, a relevant message is returned.
- This does **not** affect other active sessions.
`,
  })
  @ApiBody({
    description: 'Payload containing the sessionId to revoke',
    type: LogoutSessionDto,
    examples: {
      validExample: {
        summary: 'Example logout request',
        value: { sessionId: 'b9f7f3d3-3a6e-4f34-bc23-8490dfdf1234' },
      },
    },
  })
  @ApiOkResponse({
    description: 'Session revoked successfully',
    schema: {
      example: {
        message: 'Session has been revoked successfully.',
        data: { sessionId: 'b9f7f3d3-3a6e-4f34-bc23-8490dfdf1234' },
        meta: { status: 'success', code: 'SESSION_REVOKED' },
        ts: '2025-10-11T12:30:45.123Z',
      },
    },
  })
  @ApiBadRequestResponse({
    description: 'Missing tenant ID or user identity',
    schema: {
      oneOf: [
        {
          example: {
            message:
              'Logout failed because tenant environment is not initialized.',
            data: null,
            meta: {
              status: 'error',
              code: 'TENANT_CONNECTION_MISSING',
              details: { tenantId: 'tenant_abc' },
            },
            ts: '2025-10-11T12:30:45.123Z',
          },
        },
        {
          example: {
            message: 'Logout request missing user identity.',
            data: null,
            meta: { status: 'error', code: 'USER_ID_MISSING' },
            ts: '2025-10-11T12:30:45.123Z',
          },
        },
      ],
    },
  })
  @ApiNotFoundResponse({
    description: 'Session not found or already logged out',
    schema: {
      example: {
        message: 'Session not found or already logged out.',
        data: null,
        meta: {
          status: 'error',
          code: 'SESSION_NOT_FOUND',
          details: { sessionId: 'b9f7f3d3-3a6e-4f34-bc23-8490dfdf1234' },
        },
        ts: '2025-10-11T12:30:45.123Z',
      },
    },
  })
  @ApiInternalServerErrorResponse({
    description: 'Unexpected error while revoking session',
    schema: {
      example: {
        message: 'Logout failed due to a system error. Please try again later.',
        data: null,
        meta: {
          status: 'error',
          code: 'INTERNAL_ERROR',
          error: 'Database update failed',
        },
        ts: '2025-10-11T12:30:45.123Z',
      },
    },
  })
  async logoutSession(
    @Headers('x-tenant-id') tenantId: string,
    @Req() req: any,
    @Body() dto: LogoutSessionDto,
  ) {
    if (!tenantId) throw new BadRequestException('x-tenant-id is required');
    const safeReq = {
      user: req.user,
      headers: {
        'user-agent': req.headers['user-agent'] || 'unknown',
        host:
          req.headers['host'] | req.ip ||
          req.connection?.remoteAddress ||
          '0.0.0.0',
      },
    };

    const result = await this.sendSafe<any>('auth.logoutSession', {
      tenantId,
      req: safeReq,
      sessionId: dto.sessionId,
    });
    return result;
  }

  // ───────────────────────────────
  // Logout all sessions
  // ───────────────────────────────
  @UseGuards(JwtAuthGuard, JwtSessionGuard)
  @Post('logout/all')
  @ApiBearerAuth('bearer')
  @ApiOperation({
    summary: 'Logout All Active Sessions',
    description: `
Revokes **all active user sessions** for the authenticated user.
`,
  })
  @ApiOkResponse({
    description: 'All sessions revoked successfully',
    schema: {
      example: {
        message: 'All sessions have been revoked successfully.',
        data: { revokedCount: 3 },
        meta: { status: 'success', code: 'ALL_SESSIONS_REVOKED' },
        ts: '2025-10-11T12:30:45.123Z',
      },
    },
  })
  @ApiBadRequestResponse({
    description: 'Missing tenant ID or invalid user context',
    schema: {
      oneOf: [
        {
          example: {
            message:
              'Unable to perform logout-all because tenant environment is not initialized.',
            data: null,
            meta: {
              status: 'error',
              code: 'TENANT_CONNECTION_MISSING',
              details: { tenantId: 'tenant_abc' },
            },
            ts: '2025-10-11T12:30:45.123Z',
          },
        },
        {
          example: {
            message: 'Logout-all request missing user identity.',
            data: null,
            meta: { status: 'error', code: 'USER_ID_MISSING' },
            ts: '2025-10-11T12:30:45.123Z',
          },
        },
      ],
    },
  })
  @ApiInternalServerErrorResponse({
    description: 'Unexpected error during logout-all operation',
    schema: {
      example: {
        message:
          'Logout-all failed due to a system error. Please try again later.',
        data: null,
        meta: {
          status: 'error',
          code: 'INTERNAL_ERROR',
          error: 'Database connection lost',
        },
        ts: '2025-10-11T12:30:45.123Z',
      },
    },
  })
  async logoutAll(@Headers('x-tenant-id') tenantId: string, @Req() req: any) {
    if (!tenantId) throw new BadRequestException('x-tenant-id is required');
    const safeReq = {
      user: req.user,
      headers: {
        'user-agent': req.headers['user-agent'] || 'unknown',
        host:
          req.headers['host'] | req.ip ||
          req.connection?.remoteAddress ||
          '0.0.0.0',
      },
    };

    const result = await this.sendSafe<any>('auth.logoutAll', {
      tenantId,
      req: safeReq,
    });
    return result;
  }

  // ───────────────────────────────
  // Refresh tokens
  // ───────────────────────────────
  @UseGuards(JwtAuthGuard, JwtSessionGuard)
  @Post('refresh')
  @ApiBearerAuth('bearer')
  @ApiOperation({
    summary: 'Refresh Access and Refresh Tokens',
    description: `
Rotates and issues a new **access token** and **refresh token** when the current access token has expired.
`,
  })
  @ApiBody({
    description: 'Payload containing refresh token for rotation',
    type: RefreshDto,
    examples: {
      validExample: {
        summary: 'Example refresh request',
        value: { refreshToken: 'existing-jwt-refresh-token' },
      },
    },
  })
  @ApiOkResponse({
    description: 'Tokens refreshed successfully',
    schema: {
      example: {
        message: 'Access and refresh tokens have been renewed successfully.',
        data: {
          accessToken: 'new-jwt-access-token',
          refreshToken: 'new-jwt-refresh-token',
        },
        meta: { status: 'success', code: 'TOKENS_REFRESHED' },
        ts: '2025-10-11T12:30:45.123Z',
      },
    },
  })
  @ApiUnauthorizedResponse({
    description: 'Invalid or expired refresh token or session mismatch',
    schema: {
      oneOf: [
        {
          example: {
            message:
              'The provided refresh token is invalid or has expired. Please log in again.',
            data: null,
            meta: { status: 'error', code: 'INVALID_REFRESH_TOKEN' },
            ts: '2025-10-11T12:30:45.123Z',
          },
        },
        {
          example: {
            message: 'Session not found or expired. Please log in again.',
            data: null,
            meta: {
              status: 'error',
              code: 'SESSION_NOT_FOUND',
              details: { sessionId: 'uuid' },
            },
            ts: '2025-10-11T12:30:45.123Z',
          },
        },
      ],
    },
  })
  @ApiBadRequestResponse({
    description: 'Missing tenant ID or invalid payload',
    schema: {
      example: {
        message:
          'Token refresh failed because tenant environment is not initialized.',
        data: null,
        meta: {
          status: 'error',
          code: 'TENANT_CONNECTION_MISSING',
          details: { tenantId: 'tenant_abc' },
        },
        ts: '2025-10-11T12:30:45.123Z',
      },
    },
  })
  @ApiInternalServerErrorResponse({
    description: 'Unexpected error while refreshing tokens',
    schema: {
      example: {
        message:
          'Token refresh failed due to a system error. Please try again later.',
        data: null,
        meta: {
          status: 'error',
          code: 'INTERNAL_ERROR',
          error: 'Redis connection lost',
        },
        ts: '2025-10-11T12:30:45.123Z',
      },
    },
  })
  async refresh(
    @Headers('x-tenant-id') tenantId: string,
    @Req() req: any,
    @Body() dto: RefreshDto,
  ) {
    if (!tenantId) throw new BadRequestException('x-tenant-id is required');
    const safeReq = {
      user: req.user,
      headers: {
        'user-agent': req.headers['user-agent'] || 'unknown',
        host:
          req.headers['host'] | req.ip ||
          req.connection?.remoteAddress ||
          '0.0.0.0',
      },
    };

    const result = await this.sendSafe<any>('auth.refresh', {
      tenantId,
      req: safeReq,
      refreshToken: dto.refreshToken,
    });
    return result;
  }

  // ───────────────────────────────
  // Change role
  // ───────────────────────────────
  // @Public()
  @Roles('admin')
  @Post('change-role')
  @ApiBearerAuth('bearer')
  @ApiOperation({
    summary: 'Change User Role (Admin Only)',
    description: `
Allows an **admin** to update another user's role within the same tenant environment.
`,
  })
  @ApiBody({
    description: 'Payload to update a user’s role',
    schema: {
      type: 'object',
      properties: {
        userId: {
          type: 'string',
          example: 'f9b6de24-1f5d-4b55-b50e-1fab249bb552',
          description: 'User ID to update role for',
        },
        newRole: {
          type: 'string',
          example: 'admin',
          description: 'New role to assign (e.g., user, manager, admin)',
        },
      },
      required: ['userId', 'newRole'],
    },
  })
  @ApiOkResponse({
    description: 'User role updated successfully',
    schema: {
      example: {
        message: 'User role has been updated successfully.',
        data: {
          id: 'uuid',
          username: 'johndoe',
          email: 'john@example.com',
          previousRole: 'user',
          newRole: 'admin',
        },
        meta: { status: 'success', code: 'USER_ROLE_UPDATED' },
        ts: '2025-10-11T12:30:45.123Z',
      },
    },
  })
  @ApiBadRequestResponse({
    description: 'User not found or tenant connection missing',
    schema: {
      oneOf: [
        {
          example: {
            message:
              'Role update failed because tenant environment is not initialized.',
            data: null,
            meta: {
              status: 'error',
              code: 'TENANT_CONNECTION_MISSING',
              details: { tenantId: 'tenant_abc' },
            },
            ts: '2025-10-11T12:30:45.123Z',
          },
        },
        {
          example: {
            message:
              'No user found with the provided identifier. Please verify and try again.',
            data: null,
            meta: {
              status: 'error',
              code: 'USER_NOT_FOUND',
              details: { userId: 'f9b6de24-1f5d-4b55-b50e-1fab249bb552' },
            },
            ts: '2025-10-11T12:30:45.123Z',
          },
        },
      ],
    },
  })
  @ApiForbiddenResponse({
    description: 'User lacks admin privileges',
    schema: {
      example: {
        message: 'Access denied: Admin role required to change user roles.',
        data: null,
        meta: { status: 'error', code: 'FORBIDDEN' },
        ts: '2025-10-11T12:30:45.123Z',
      },
    },
  })
  @ApiInternalServerErrorResponse({
    description: 'Unexpected error during role update',
    schema: {
      example: {
        message:
          'Role update failed due to a system error. Please try again later.',
        data: null,
        meta: {
          status: 'error',
          code: 'INTERNAL_ERROR',
          error: 'Database write conflict',
        },
        ts: '2025-10-11T12:30:45.123Z',
      },
    },
  })
  async changeUserRole(
    @Headers('x-tenant-id') tenantId: string,
    @Body('userId') userId: string,
    @Body('newRole') newRole: string,
    @Req() req: any,
  ) {
    if (!tenantId) throw new BadRequestException('x-tenant-id is required');
    const safeReq = {
      user: req.user,
      headers: {
        'user-agent': req.headers['user-agent'] || 'unknown',
        host:
          req.headers['host'] | req.ip ||
          req.connection?.remoteAddress ||
          '0.0.0.0',
      },
    };

    const result = await this.sendSafe<any>('auth.changeUserRole', {
      tenantId,
      userId,
      newRole,
      req: safeReq,
    });
    return result;
  }

  // ───────────────────────────────
  // Get Current User (from Access Token)
  // ───────────────────────────────
  @UseGuards(JwtAuthGuard)
  @Get('me')
  @ApiBearerAuth('bearer')
  @ApiOperation({
    summary: 'Get Current User Profile',
    description: `
Returns the currently authenticated user's profile information based on the access token.  
This endpoint extracts the JWT access token from the request header and fetches the user's latest details from the database through the Auth microservice.
    `,
  })
  @ApiOkResponse({
    description: 'User retrieved successfully',
    schema: {
      example: {
        message: 'Current user retrieved successfully.',
        data: {
          id: '66a0a2f47b85d048ae5b11d2',
          username: 'john.doe',
          name: 'John Doe',
          email: 'john@example.com',
          mobile: '+8801711111111',
          role: 'admin',
          tenantId: 'aero1',
          sessionId: 'f67a1c5d-59ea-4322-8edb-ff1815b1f38e',
          lastLoginAt: '2025-10-25T15:42:10.125Z',
          createdAt: '2025-01-10T12:30:45.123Z',
          updatedAt: '2025-10-25T15:42:10.125Z',
        },
        meta: {
          status: 'success',
          code: 'CURRENT_USER_OK',
        },
        ts: '2025-10-26T13:05:00.235Z',
      },
    },
  })
  @ApiUnauthorizedResponse({
    description: 'Invalid or expired access token',
    schema: {
      example: {
        message: 'Invalid or expired access token.',
        data: null,
        meta: {
          status: 'error',
          code: 'INVALID_ACCESS_TOKEN',
        },
        ts: '2025-10-26T13:05:00.235Z',
      },
    },
  })
  @ApiBadRequestResponse({
    description: 'Missing tenant ID',
    schema: {
      example: {
        message: 'x-tenant-id is required',
        error: 'Bad Request',
        statusCode: 400,
      },
    },
  })
  @ApiInternalServerErrorResponse({
    description: 'Unexpected error occurred while retrieving current user',
    schema: {
      example: {
        message: 'Failed to retrieve current user.',
        data: null,
        meta: {
          status: 'error',
          code: 'INTERNAL_ERROR',
          error: 'Database connection lost',
        },
        ts: '2025-10-26T13:05:00.235Z',
      },
    },
  })
  async getCurrentUser(
    @Headers('x-tenant-id') tenantId: string,
    @Req() req: any,
  ) {
    if (!tenantId) throw new BadRequestException('x-tenant-id is required');

    const safeReq = {
      user: req.user,
      headers: {
        'user-agent': req.headers['user-agent'] || 'unknown',
        host:
          req.headers['host'] | req.ip ||
          req.connection?.remoteAddress ||
          '0.0.0.0',
      },
    };

    const accessToken =
      req.headers['authorization'] || req.headers['Authorization'];
    if (!accessToken) {
      throw new BadRequestException('Authorization header is required');
    }

    const token = accessToken.replace(/^Bearer\s+/i, '');

    const result = await this.sendSafe<any>('auth.get-current-user', {
      tenantId,
      token,
      req: safeReq,
    });

    return result;
  }
}
