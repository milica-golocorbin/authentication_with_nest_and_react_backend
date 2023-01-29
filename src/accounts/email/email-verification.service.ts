import { Injectable } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { JwtService } from "@nestjs/jwt";
import { NodemailerService } from "./nodemailer.service";

@Injectable()
export class EmailVerificationService {
  constructor(
    private configService: ConfigService,
    private nodemailerService: NodemailerService,
    private jwtService: JwtService,
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

    const text = `Welcome to the application. To confirm the email address, click here: ${url}`;

    return this.nodemailerService.sendMail({
      to: email,
      subject: "Email Verification",
      text,
    });
  }
}
