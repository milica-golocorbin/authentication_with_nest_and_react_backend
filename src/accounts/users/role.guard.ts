import { Role } from "./role.enum";
import { CanActivate, ExecutionContext, mixin, Type } from "@nestjs/common";
import { RequestWithUser } from "../authentication/request-with-user.interface";

export const RoleGuard = (role: Role): Type<CanActivate> => {
  class RoleGuardMixin implements CanActivate {
    canActivate(context: ExecutionContext) {
      const request = context.switchToHttp().getRequest<RequestWithUser>();
      const user = request.user;

      return user?.role === role;
    }
  }

  return mixin(RoleGuardMixin);
};
