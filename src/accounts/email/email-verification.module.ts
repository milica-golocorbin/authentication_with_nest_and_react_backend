import { Module } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { NodemailerModule } from "./nodemailer.module";
import { JwtModule } from "@nestjs/jwt";
import { UsersModule } from "../users/users.module";
import { EmailVerificationService } from "./email-verification.service";
import { EmailVerificationController } from "./email-verification.controller";

@Module({
  imports: [
    NodemailerModule.registerAsync({
      inject: [ConfigService],
      useFactory: (configService: ConfigService) => ({
        service: configService.get("EMAIL_SERVICE"),
        user: configService.get("EMAIL_USER"),
        password: configService.get("EMAIL_PASSWORD"),
      }),
    }),
    JwtModule.register({}),
    UsersModule,
  ],
  providers: [EmailVerificationService],
  exports: [EmailVerificationService],
  controllers: [EmailVerificationController],
})
export class EmailVerificationModule {}
