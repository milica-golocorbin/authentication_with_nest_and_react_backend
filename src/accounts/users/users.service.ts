import { Injectable } from "@nestjs/common";
import { InjectRepository } from "@nestjs/typeorm";
import { Repository } from "typeorm";
import { User } from "./user.entity";
import { CreateUserDto } from "./create-user.dto";
import * as bcrypt from "bcrypt";

@Injectable()
export class UsersService {
  constructor(@InjectRepository(User) private usersRepo: Repository<User>) {}

  async getUserByEmail(email: string): Promise<User> | null {
    // Finds first entity by email. If entity was not found in the database, it returns null.
    return await this.usersRepo.findOne({ where: { email } });
  }

  async createUser(createUserDto: CreateUserDto): Promise<User> {
    const hashedPassword = await bcrypt.hash(createUserDto.password, 10);
    const newUser = this.usersRepo.create({
      ...createUserDto,
      password: hashedPassword,
    });
    // Saves a entity in the database. If entity does not exist in the database then inserts, otherwise updates.
    return await this.usersRepo.save(newUser);
  }
}
