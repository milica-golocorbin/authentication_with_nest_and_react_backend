import {
  Column,
  CreateDateColumn,
  Entity,
  Index,
  PrimaryGeneratedColumn,
  UpdateDateColumn,
} from "typeorm";
import { Exclude } from "class-transformer";
import { Role } from "./role.enum";

@Entity("users")
export class User {
  @PrimaryGeneratedColumn()
  public id: number;

  @Index()
  @Column({ unique: true })
  public email: string;

  @Column({ name: "first_name" })
  public firstName: string;

  @Column({ name: "hashed_password" })
  @Exclude()
  public password: string;

  @Column({ name: "refresh_jwt_token", nullable: true })
  @Exclude()
  public refreshJwtToken?: string;

  @Column({ name: "is_verified", default: false })
  public isVerified: boolean;

  @Column({ type: "enum", enum: Role, default: Role.USER })
  public role: Role;

  @CreateDateColumn({ name: "created_at" })
  public createdAt: Date;

  @UpdateDateColumn({ name: "updated_at" })
  public updatedAt: Date;

  constructor(partial: Partial<User>) {
    Object.assign(this, partial);
  }
}
