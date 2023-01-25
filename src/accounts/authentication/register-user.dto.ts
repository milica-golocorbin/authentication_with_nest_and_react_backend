import { IsEmail, IsString, MaxLength, MinLength } from "class-validator";

export class RegisterUserDto {
  @IsString()
  @MinLength(4)
  @MaxLength(16)
  readonly firstName: string;

  @IsString()
  @IsEmail()
  readonly email: string;

  @IsString()
  @MinLength(8)
  readonly password: string;
}
