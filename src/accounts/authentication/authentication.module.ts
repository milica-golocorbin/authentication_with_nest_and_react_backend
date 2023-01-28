import { Module } from "@nestjs/common";
import { PassportModule } from "@nestjs/passport";
import { JwtModule } from "@nestjs/jwt";
import { LocalStrategy } from "./passport/strategies/local.strategy";
import { JwtStrategy } from "./passport/strategies/jwt.strategy";
import { JwtRefreshTokenStrategy } from "./passport/strategies/jwt-refresh.strategy";
import { UsersModule } from "../users/users.module";
import { AuthenticationService } from "./authentication.service";
import { AuthenticationController } from "./authentication.controller";
import { EmailVerificationModule } from "../email/email-verification.module";

@Module({
  imports: [
    UsersModule,
    PassportModule,
    JwtModule.register({}),
    EmailVerificationModule,
  ],
  providers: [
    AuthenticationService,
    LocalStrategy,
    JwtStrategy,
    JwtRefreshTokenStrategy,
  ],
  exports: [AuthenticationService],
  controllers: [AuthenticationController],
})
export class AuthenticationModule {}
