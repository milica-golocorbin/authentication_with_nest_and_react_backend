import { BadRequestException, Injectable } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { JwtService } from "@nestjs/jwt";
import { NodemailerService } from "./nodemailer.service";
import { UsersService } from "./../users/users.service";

@Injectable()
export class EmailVerificationService {
  constructor(
    private configService: ConfigService,
    private nodemailerService: NodemailerService,
    private jwtService: JwtService,
    private usersService: UsersService,
  ) {}

  public sendVerificationLink(email: string) {
    const payload = { email };

    const token = this.jwtService.sign(payload, {
      secret: this.configService.get("JWT_VERIFICATION_TOKEN_SECRET"),
      expiresIn: `${this.configService.get(
        "JWT_VERIFICATION_TOKEN_EXPIRATION_TIME",
      )}s`,
    });

    const url = `${this.configService.get(
      "EMAIL_VERIFICATION_URL",
    )}?token=${token}`;

    const text = `Welcome to the application. To verify the email address, click here: ${url}`;

    return this.nodemailerService.sendMail({
      to: email,
      subject: "Email Verification",
      text,
    });
  }

  public async decodeVerificationToken(token: string) {
    try {
      const payload = await this.jwtService.verify(token, {
        secret: this.configService.get("JWT_VERIFICATION_TOKEN_SECRET"),
      });
      if (payload.hasOwnProperty("email")) {
        return payload.email;
      }
      throw new BadRequestException();
    } catch (error) {
      if (error?.name === "TokenExpiredError") {
        throw new BadRequestException("Email verification token expired.");
      }
      throw new BadRequestException("Bad verification token.");
    }
  }

  public async verifyEmail(email: string) {
    const user = await this.usersService.getUserByEmail(email);
    if (user.isVerified) {
      throw new BadRequestException("Email already verified.");
    }
    await this.usersService.markEmailAsVerified(email);
  }

  public async resendVerificationLink(userId: number) {
    const user = await this.usersService.getUserById(userId);
    if (user.isVerified) {
      throw new BadRequestException("Email already verified.");
    }
    await this.sendVerificationLink(user.email);
  }
}
