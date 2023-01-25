import { HttpException, HttpStatus } from "@nestjs/common";
import { Injectable } from "@nestjs/common/decorators";
import { ConfigService } from "@nestjs/config";
import { UsersService } from "../users/users.service";
import { RegisterUserDto } from "./register-user.dto";
import * as bcrypt from "bcrypt";

@Injectable()
export class AuthenticationService {
  constructor(
    private configService: ConfigService,
    private usersService: UsersService,
  ) {}

  public async registerUser(registerUserDto: RegisterUserDto) {
    // checking to see if user already exists; this function returns either null or User
    const user = await this.usersService.getUserByEmail(registerUserDto.email);

    if (!user?.hasOwnProperty("email")) {
      // TODO: SENDING VERIFICATION LINK BEFORE SAVING USER
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
}
