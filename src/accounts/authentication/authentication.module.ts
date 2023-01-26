import { Module } from "@nestjs/common";
import { PassportModule } from "@nestjs/passport";
import { JwtModule } from "@nestjs/jwt";
import { LocalStrategy } from "./passport/strategies/local.strategy";
import { JwtStrategy } from "./passport/strategies/jwt.strategy";
import { UsersModule } from "../users/users.module";
import { AuthenticationService } from "./authentication.service";
import { AuthenticationController } from "./authentication.controller";

@Module({
  imports: [UsersModule, PassportModule, JwtModule.register({})],
  providers: [AuthenticationService, LocalStrategy, JwtStrategy],
  exports: [AuthenticationService],
  controllers: [AuthenticationController],
})
export class AuthenticationModule {}
