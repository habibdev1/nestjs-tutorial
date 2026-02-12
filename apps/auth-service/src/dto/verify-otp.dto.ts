import { IsString, IsNotEmpty, IsUUID, Length } from 'class-validator';

export class VerifyOtpDto {
  @IsUUID()
  loginId: string; // temporary ID that ties to OTP record in Redis

  @IsString()
  @IsNotEmpty()
  @Length(6, 6)
  otp: string;

  @IsString()
  deviceName?: string; // optional label e.g. "Chrome on Mac"
}
