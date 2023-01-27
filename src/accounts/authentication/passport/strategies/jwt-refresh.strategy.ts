import { Request } from "express";
import { HttpException, HttpStatus, Injectable } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { UsersService } from "src/accounts/users/users.service";
import { PassportStrategy } from "@nestjs/passport";
import { ExtractJwt, Strategy } from "passport-jwt";
import { User } from "../../../users/user.entity";

@Injectable()
export class JwtRefreshTokenStrategy extends PassportStrategy(
  Strategy,
  "jwt-refresh-token",
) {
  constructor(
    private configService: ConfigService,
    private usersService: UsersService,
  ) {
    super({
      jwtFromRequest: ExtractJwt.fromExtractors([
        (request: Request) => {
          if (!request?.cookies?.Refresh) {
            throw new HttpException(
              "Token expired. Please login.",
              HttpStatus.NOT_FOUND,
            );
          }
          return request?.cookies?.Refresh;
        },
      ]),
      secretOrKey: configService.get("JWT_REFRESH_TOKEN_SECRET"),
      passReqToCallback: true,
    });
  }

  async validate(request: Request, payload: { userId: number }): Promise<User> {
    const refreshToken = request.cookies?.Refresh;
    const user = await this.usersService.getUserByRefreshToken(
      refreshToken,
      payload.userId,
    );
    return user;
  }
}
