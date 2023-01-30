import { HttpException, HttpStatus, Injectable } from "@nestjs/common";
import { InjectRepository } from "@nestjs/typeorm";
import { Repository } from "typeorm";
import { User } from "./user.entity";
import { UserCreateDto } from "./user-create.dto";
import * as bcrypt from "bcrypt";

@Injectable()
export class UsersService {
  constructor(@InjectRepository(User) private usersRepo: Repository<User>) {}

  // READING DATABASE
  async getUserByEmail(email: string): Promise<User> | null {
    // Finds first entity by email. If entity was not found in the database, it returns null.
    return await this.usersRepo.findOne({ where: { email } });
  }

  //  (called by JwtStrategy)
  async getUserById(id: number) {
    const user = await this.usersRepo.findOne({ where: { id } });
    if (!user) {
      throw new HttpException("User does not exist.", HttpStatus.NOT_FOUND);
    }
    return user;
  }

  //  (called by JwtRefreshStrategy)
  public async getUserByRefreshToken(refreshToken: string, userId: number) {
    const user = await this.getUserById(userId);
    const isRefreshTokenMatching = await bcrypt.compare(
      refreshToken,
      user.refreshJwtToken,
    );
    if (!isRefreshTokenMatching) {
      throw new HttpException("Token expired.", HttpStatus.BAD_REQUEST);
    }
    return user;
  }
  // READING DATABASE

  // CREATE - SAVING TO DATABASE METHODS
  async createUser(userCreateDto: UserCreateDto): Promise<User> {
    const hashedPassword = await bcrypt.hash(userCreateDto.password, 10);
    const newUser = this.usersRepo.create({
      ...userCreateDto,
      password: hashedPassword,
    });
    // Saves a entity in the database. If entity does not exist in the database then inserts, otherwise updates.
    return await this.usersRepo.save(newUser);
  }

  // hashing refresh token and saving hashed refresh token in the users table
  async saveRefreshToken(refreshToken: string, userId: number) {
    const hashedRefreshToken = await bcrypt.hash(refreshToken, 10);
    return await this.usersRepo.update(userId, {
      refreshJwtToken: hashedRefreshToken,
    });
    // Updates entity partially. Unlike save method executes a primitive operation without cascades, relations and other operations included. Executes fast and efficient UPDATE query. Does not check if entity exist in the database.
  }
  // CREATE - SAVING TO DATABASE METHODS

  //UPDATING DATABASE
  async removeRefreshToken(userId: number) {
    return await this.usersRepo.update(userId, {
      refreshJwtToken: null,
    });
  }

  async markEmailAsVerified(email: string) {
    return await this.usersRepo.update(
      { email },
      {
        isVerified: true,
      },
    );
  }
  //UPDATING DATABASE
}
