import { Module } from "@nestjs/common";
import { PassportModule } from "@nestjs/passport";
import { UsersModule } from "../users/users.module";
import { AuthenticationService } from "./authentication.service";
import { LocalStrategy } from "./passport/strategies/local.strategy";
import { AuthenticationController } from "./authentication.controller";

@Module({
  imports: [PassportModule, UsersModule],
  providers: [AuthenticationService, LocalStrategy],
  exports: [AuthenticationService],
  controllers: [AuthenticationController],
})
export class AuthenticationModule {}
