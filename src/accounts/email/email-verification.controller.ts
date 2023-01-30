import {
  Body,
  ClassSerializerInterceptor,
  Controller,
  Post,
  Req,
  UseGuards,
  UseInterceptors,
} from "@nestjs/common";
import { RequestWithUser } from "../authentication/request-with-user.interface";
import { EmailVerificationService } from "./email-verification.service";
import { JwtAuthenticationGuard } from "../authentication/passport/guards/jwt-authentication.guard";
import { EmailVerifyDto } from "./email-verification.dto";

@Controller("email-verification")
@UseInterceptors(ClassSerializerInterceptor)
export class EmailVerificationController {
  readonly emailVerificationService: EmailVerificationService;

  @Post("verify")
  async verify(@Body() emailVerifyDto: EmailVerifyDto) {
    const email: string =
      await this.emailVerificationService.decodeVerificationToken(
        emailVerifyDto.token,
      );
    await this.emailVerificationService.verifyEmail(email);
  }

  @UseGuards(JwtAuthenticationGuard)
  @Post("resend")
  async resend(@Req() request: RequestWithUser) {
    await this.emailVerificationService.resendVerificationLink(request.user.id);
  }
}
