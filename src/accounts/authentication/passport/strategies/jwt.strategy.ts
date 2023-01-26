import { Request } from "express";
import { HttpException, HttpStatus, Injectable } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { PassportStrategy } from "@nestjs/passport";
import { ExtractJwt, Strategy } from "passport-jwt";
import { UsersService } from "src/accounts/users/users.service";
import { User } from "src/accounts/users/user.entity";

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy, "jwt") {
  constructor(
    private configService: ConfigService,
    private usersService: UsersService,
  ) {
    super({
      jwtFromRequest: ExtractJwt.fromExtractors([
        (request: Request) => {
          if (!request?.cookies?.Authentication) {
            throw new HttpException("Token expired.", HttpStatus.NOT_FOUND);
          }
          return request?.cookies?.Authentication;
        },
      ]),
      secretOrKey: configService.get("JWT_ACCESS_TOKEN_SECRET"),
    });
  }

  async validate(payload: { userId: number }): Promise<User> {
    const user = await this.usersService.getUserById(payload.userId);
    return user;
  }
}
