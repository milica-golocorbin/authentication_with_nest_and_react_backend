import { Request } from "express";
import { User } from "src/accounts/users/user.entity";

export interface RequestWithUser extends Request {
  user: User;
}
