import { IsUUID } from 'class-validator';

export class LogoutSessionDto {
  @IsUUID()
  sessionId: string;
}
