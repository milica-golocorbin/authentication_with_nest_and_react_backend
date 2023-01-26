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
import { JwtAuthenticationGuard } from "./passport/guards/jwt-authentication.guard";

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
    // creating access token and saving it to the cookie
    const accessTokenCookie = this.authenticationService.createAccessToken(
      user.id,
    );
    request.res.setHeader("Set-Cookie", accessTokenCookie);
    return user;
  }

  @UseGuards(JwtAuthenticationGuard)
  @HttpCode(204)
  @Post("logout")
  async logout(@Req() request: RequestWithUser) {
    // removing access token from the cookie
    request.res.setHeader("Set-Cookie", [
      "Authentication=; HttpOnly; Path=/; Max-Age=0",
      "Refresh=; HttpOnly; Path=/; Max-Age=0",
    ]);
  }
}
