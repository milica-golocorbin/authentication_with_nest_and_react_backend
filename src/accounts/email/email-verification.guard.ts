import {
  Injectable,
  CanActivate,
  ExecutionContext,
  UnauthorizedException,
} from "@nestjs/common";
import { RequestWithUser } from "../authentication/request-with-user.interface";

@Injectable()
export class EmailVerificationGuard implements CanActivate {
  canActivate(context: ExecutionContext) {
    const request: RequestWithUser = context.switchToHttp().getRequest();

    if (!request.user?.isVerified) {
      throw new UnauthorizedException("Verify your email first.");
    }

    return true;
  }
}
