import { IsString, IsNotEmpty } from 'class-validator';

export class LoginDto {
  @IsString()
  @IsNotEmpty()
  usernameOrEmailOrMobile: string;

  @IsString()
  @IsNotEmpty()
  password: string;
}
