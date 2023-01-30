import { IsNotEmpty, IsString } from "class-validator";

export class EmailVerifyDto {
  @IsString()
  @IsNotEmpty()
  token: string;
}
