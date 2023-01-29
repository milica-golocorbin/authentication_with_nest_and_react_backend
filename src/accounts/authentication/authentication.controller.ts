import {
  Body,
  ClassSerializerInterceptor,
  Controller,
  Get,
  HttpCode,
  Post,
  Req,
  UseGuards,
  UseInterceptors,
} from "@nestjs/common";
import { AuthenticationService } from "./authentication.service";
import { EmailVerificationService } from "./../email/email-verification.service";
import { UsersService } from "../users/users.service";
import { RegisterUserDto } from "./register-user.dto";
import { RequestWithUser } from "./request-with-user.interface";
import { LocalAuthenticationGuard } from "./passport/guards/local-authentication.guard";
import { JwtAuthenticationGuard } from "./passport/guards/jwt-authentication.guard";
import { JwtRefreshAuthenticationGuard } from "./passport/guards/jwt-refresh-authentication.guard";

@UseInterceptors(ClassSerializerInterceptor)
@Controller("auth")
export class AuthenticationController {
  constructor(
    readonly authenticationService: AuthenticationService,
    readonly emailVerificationService: EmailVerificationService,
    readonly usersService: UsersService,
  ) {}

  @Post("register")
  async register(@Body() registerUserDto: RegisterUserDto) {
    const user = await this.authenticationService.registerUser(registerUserDto);
    await this.emailVerificationService.sendVerificationLink(
      registerUserDto.email,
    );
    return { user, message: "Visit email to verify your account." };
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
    // creating refresh token and saving it to the cookie
    const { cookie: refreshTokenCookie, refreshToken } =
      this.authenticationService.createRefreshToken(user.id);
    // saving refresh token to database
    await this.usersService.saveRefreshToken(refreshToken, user.id);

    request.res.setHeader("Set-Cookie", [
      accessTokenCookie,
      refreshTokenCookie,
    ]);
    return user;
  }

  @UseGuards(JwtAuthenticationGuard)
  @HttpCode(204)
  @Post("logout")
  async logout(@Req() request: RequestWithUser) {
    // removing saved refresh token from the users table
    await this.usersService.removeRefreshToken(request.user.id);
    // removing access token from the cookie
    request.res.setHeader("Set-Cookie", [
      "Authentication=; HttpOnly; Path=/; Max-Age=0",
      "Refresh=; HttpOnly; Path=/; Max-Age=0",
    ]);
  }

  @UseGuards(JwtRefreshAuthenticationGuard)
  @Get("refresh")
  refresh(@Req() request: RequestWithUser) {
    // creating new access token and saving it to the cookie
    const accessTokenCookie = this.authenticationService.createAccessToken(
      request.user.id,
    );
    request.res.setHeader("Set-Cookie", accessTokenCookie);
    return request.user;
  }
}
