import { Module } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { NodemailerModule } from "./nodemailer.module";

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
  ],
})
export class EmailVerificationModule {}
