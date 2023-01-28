import { Module } from "@nestjs/common";
import { ConfigurableEmailModule } from "./nodemailer.module-definition";
import { NodemailerService } from "./nodemailer.service";

@Module({
  providers: [NodemailerService],
  exports: [NodemailerService],
})
export class NodemailerModule extends ConfigurableEmailModule {}
