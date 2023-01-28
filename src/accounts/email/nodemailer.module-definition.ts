import { ConfigurableModuleBuilder } from "@nestjs/common";
import { NodemailerOptionsInterface } from "./nodemailer-options.interface";

export const {
  ConfigurableModuleClass: ConfigurableEmailModule,
  MODULE_OPTIONS_TOKEN: EMAIL_CONFIG_OPTIONS,
} = new ConfigurableModuleBuilder<NodemailerOptionsInterface>().build();
