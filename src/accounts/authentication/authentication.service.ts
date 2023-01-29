import { HttpException, HttpStatus } from "@nestjs/common";
import { Injectable } from "@nestjs/common/decorators";
import { ConfigService } from "@nestjs/config";
import { JwtService } from "@nestjs/jwt";
import { UsersService } from "../users/users.service";
import { RegisterUserDto } from "./register-user.dto";
import * as bcrypt from "bcrypt";

@Injectable()
export class AuthenticationService {
  constructor(
    private configService: ConfigService,
    private jwtService: JwtService,
    private usersService: UsersService,
  ) {}

  public async registerUser(registerUserDto: RegisterUserDto) {
    // checking to see if user already exists; this function returns either null or User
    const user = await this.usersService.getUserByEmail(registerUserDto.email);

    if (!user?.hasOwnProperty("email")) {
      return this.usersService.createUser(registerUserDto);
    } else {
      throw new HttpException(
        "User with that email already exists.",
        HttpStatus.BAD_REQUEST,
      );
    }
  }

  public async getAuthenticatedUser(email: string, password: string) {
    const user = await this.usersService.getUserByEmail(email);
    // checking if user does not already exists;
    if (!user) {
      throw new HttpException(
        "Wrong credentials provided.",
        HttpStatus.BAD_REQUEST,
      );
    }
    // TODO: CHECK IF USER HAS VERIFIED HIS EMAIL
    // checking if password is correct
    const isPasswordMatching = await bcrypt.compare(password, user.password);
    if (!isPasswordMatching) {
      throw new HttpException(
        "Wrong credentials provided.",
        HttpStatus.BAD_REQUEST,
      );
    }
    return user;
  }

  // ACCESS TOKEN AND REFRESH TOKEN GENERATION START

  // creating access token and saving it to the cookie
  public createAccessToken(userId: number) {
    const payload = { userId };
    const accessToken = this.jwtService.sign(payload, {
      secret: this.configService.get("JWT_ACCESS_TOKEN_SECRET"),
      expiresIn: `${this.configService.get(
        "JWT_ACCESS_TOKEN_EXPIRATION_TIME",
      )}s`,
    });
    const cookie = `Authentication=${accessToken}; HttpOnly; Path=/; Max-Age=${this.configService.get(
      "JWT_ACCESS_TOKEN_EXPIRATION_TIME",
    )}`;

    return cookie;
  }

  // creating refresh token and saving it to the cookie
  public createRefreshToken(userId: number) {
    const payload = { userId };
    const refreshToken = this.jwtService.sign(payload, {
      secret: this.configService.get("JWT_REFRESH_TOKEN_SECRET"),
      expiresIn: `${this.configService.get(
        "JWT_REFRESH_TOKEN_EXPIRATION_TIME",
      )}s`,
    });
    const cookie = `Refresh=${refreshToken}; HttpOnly; Path=/; Max-Age=${this.configService.get(
      "JWT_REFRESH_TOKEN_EXPIRATION_TIME",
    )}`;
    return { cookie, refreshToken };
  }

  // ACCESS TOKEN AND REFRESH TOKEN GENERATION END
}
