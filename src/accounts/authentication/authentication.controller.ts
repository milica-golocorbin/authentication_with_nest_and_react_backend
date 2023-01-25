import {
  Body,
  ClassSerializerInterceptor,
  Controller,
  HttpCode,
  Post,
  Req,
  UseGuards,
  UseInterceptors,
} from "@nestjs/common";
import { AuthenticationService } from "./authentication.service";
import { RegisterUserDto } from "./register-user.dto";
import { RequestWithUser } from "./request-with-user.interface";
import { LocalAuthenticationGuard } from "./passport/guards/local-authentication.guard";

@UseInterceptors(ClassSerializerInterceptor)
@Controller("auth")
export class AuthenticationController {
  constructor(readonly authenticationService: AuthenticationService) {}

  @Post("register")
  async register(@Body() registerUserDto: RegisterUserDto) {
    return this.authenticationService.registerUser(registerUserDto);
  }

  @UseGuards(LocalAuthenticationGuard)
  @HttpCode(200)
  @Post("login")
  async login(@Req() request: RequestWithUser) {
    const user = request.user;
    return user;
  }
}
