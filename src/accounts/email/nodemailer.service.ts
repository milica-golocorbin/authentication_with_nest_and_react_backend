import { Inject, Injectable } from "@nestjs/common";
import { EMAIL_CONFIG_OPTIONS } from "./nodemailer.module-definition";
import { NodemailerOptionsInterface } from "./nodemailer-options.interface";
import * as Mail from "nodemailer/lib/mailer";
import { createTransport } from "nodemailer";

@Injectable()
export class NodemailerService {
  private nodemailerTransport: Mail;

  constructor(
    @Inject(EMAIL_CONFIG_OPTIONS) private options: NodemailerOptionsInterface,
  ) {
    this.nodemailerTransport = createTransport({
      service: options.service,
      auth: {
        user: options.user,
        pass: options.password,
      },
    });
  }

  sendMail(options: Mail.Options) {
    return this.nodemailerTransport.sendMail(options);
  }
}
