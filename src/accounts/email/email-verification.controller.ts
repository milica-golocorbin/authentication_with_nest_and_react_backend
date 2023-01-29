import { Controller } from "@nestjs/common/decorators";
import { EmailVerificationService } from "./email-verification.service";

@Controller("email-verification")
export class EmailVerificationController {
  readonly emailVerificationService: EmailVerificationService;
}
