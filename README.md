# Authentication API (NestJS, TypeORM, PostgreSQL, TS) - INITIAL CONFIGURATION

## Generating new project.

```
nest new server
```

## Installing necessary packages for environment variables and their validation, database connection, validation pipes.

```
npm i @nestjs/config joi @nestjs/typeorm typeorm pg class-validator class-transformer
```

## Create .env file at the root of the project, add it to gitignore file and populate it with variables for database, port, frontend url.

**.env**

```
POSTGRES_HOST=localhost
POSTGRES_PORT=5432
POSTGRES_USER=postgres
POSTGRES_PASSWORD=postgres
POSTGRES_DB=authentication
PORT=3000
FRONTEND_URL=http://localhost:5173
```

## Validate environment variables.

**app.module.ts**

```
import { Module } from "@nestjs/common";
import { ConfigModule } from "@nestjs/config";
import * as Joi from "joi";

@Module({
  imports: [
    ConfigModule.forRoot({
      validationSchema: Joi.object({
        POSTGRES_HOST: Joi.string().required(),
        POSTGRES_PORT: Joi.number().required(),
        POSTGRES_USER: Joi.string().required(),
        POSTGRES_PASSWORD: Joi.string().required(),
        POSTGRES_DB: Joi.string().required(),
        PORT: Joi.number(),
        FRONTEND_URL: Joi.string(),
      }),
    }),
  ],
  controllers: [],
  providers: [],
})
export class AppModule {}
```

## Connect with PostgreSQL DB, with the help of TypeORM. Create separate database.module.ts and do not forget to import it into a app.module.ts.

**db/database.module.ts**

```
import { Module } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { TypeOrmModule } from '@nestjs/typeorm';

@Module({
  imports: [
    TypeOrmModule.forRootAsync({
      inject: [ConfigService],
      useFactory: (configService: ConfigService) => ({
        type: 'postgres',
        host: configService.get('POSTGRES_HOST'),
        port: configService.get('POSTGRES_PORT'),
        username: configService.get('POSTGRES_USER'),
        password: configService.get('POSTGRES_PASSWORD'),
        database: configService.get('POSTGRES_DB'),
        autoLoadEntities: true,
        // TODO: Change synchronize later; Once you add db migrations;
        synchronize: true,
      }),
    }),
  ],
})
export class DatabaseModule {}
```

## Change port inside main.ts to read from environment variables, enable cors, enable validation of our user inputs.

**main.ts**

```
import { NestFactory } from "@nestjs/core";
import { ValidationPipe } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { AppModule } from "./app.module";

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  const configService = app.get(ConfigService);
  const port = configService.get<number>("PORT") ?? 3000;

  app.enableCors({
    origin: configService.get<string>("FRONTEND_URL"),
  });

  app.useGlobalPipes(
    new ValidationPipe({
      transform: true,
      whitelist: true,
      forbidNonWhitelisted: true,
    }),
  );

  await app.listen(port);
}
bootstrap();
```

## Start the server.

```
npm run start:dev
```

## Push to github.

```
git add .

git commit -m "initial configuration"

git push
```

# Authentication API (NestJS, TypeORM, PostgreSQL, TS) - PASSPORT JWT

## Create **accounts** folder, which will group our authentication, email verification and users as context. Each one of those will be in separate folders.

**USERS**

## Create users folder. Inside users folder add new file user.entity.ts. Entity is a class that maps to a database table.

isVerified column will be used for email verification and it will be false by default.
refreshJwtToken will be used for issuing new pair of access and refresh token and it will be null by default. When user logs out we will delete its value from database.
email will have unique constraint and to help our queries we will add index to it.
passport and refreshJwtToken have Exclude decorator, so that they are excluded from the response to the frontend. We will use Interceptors for that, later in the AuthenticationController.

**users/user.entity.ts**

```
import {
  Column,
  CreateDateColumn,
  Entity,
  PrimaryGeneratedColumn,
  UpdateDateColumn,
} from "typeorm";
import { Exclude } from "class-transformer";

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

  @CreateDateColumn({ name: "created_at" })
  public createdAt: Date;

  @UpdateDateColumn({ name: "updated_at" })
  public updatedAt: Date;

  constructor(partial: Partial<User>) {
    Object.assign(this, partial);
  }
}
```

## Add users.module.ts to users folder, to be able to manage entities with repository. We use modules to organize our application.

Our UsersModule will be added to AuthenticationModule, which we will create later.
We added UsersService to providers and exports, because we want to be able to use UsersService in other places in our accounts context.

**users/users.module.ts**

```
import { Module } from "@nestjs/common";
import { TypeOrmModule } from "@nestjs/typeorm";
import { User } from "./user.entity";

@Module({
  imports: [TypeOrmModule.forFeature([User])],
  providers: [UsersService],
  exports: [UsersService],
})
export class UsersModule {}
```

## Add users.service.ts to users folder. A job of a service is to separate the business logic from controllers.

We will use UsersService to create functions which will interact with database through our User repository.
We will hash user passwords before saving them in the database, with the help of **bcrypt**.
First we will create two functions. One for checking if user exists in database, based on email, and other for creating new user in the database.

```
npm install bcrypt
npm install -D @types/bcrypt
```

**users/users.service.ts**

```
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
```

## Add create-user.dto.ts to users folder. We use Data Transfer Object to define the format of the data sent in a request.

**users/create-user.dto.ts**

```
import { IsEmail, IsString, MaxLength, MinLength } from "class-validator";

export class CreateUserDto {
  @IsString()
  @MinLength(4)
  @MaxLength(16)
  readonly firstName: string;

  @IsString()
  @IsEmail()
  readonly email: string;

  @IsString()
  @MinLength(8)
  readonly password: string;
}
```

**AUTHENTICATION**

## Create authentication folder. Content in authentication folder will be main interface for our authentication and verification through communication with UsersService and EmailVerificationService.

## MODULE

**authentication/authentication.module.ts**

```
import { Module } from "@nestjs/common";
import { UsersModule } from "../users/users.module";
import { AuthenticationService } from "./authentication.service";

@Module({
  imports: [UsersModule],
  providers: [AuthenticationService],
  exports: [AuthenticationService],
  controllers: [],
})
export class AuthenticationModule {}
```

**Do not forget to add module to AppModule's imports array.**

## SERVICE

Basic logic for registering and logging in users. These functions will be interface for PassportJS.

**authentication/authentication.service.ts**

```
import { HttpException, HttpStatus } from "@nestjs/common";
import { Injectable } from "@nestjs/common/decorators";
import { ConfigService } from "@nestjs/config";
import { UsersService } from "../users/users.service";
import { RegisterUserDto } from "./register-user.dto";
import * as bcrypt from "bcrypt";

@Injectable()
export class AuthenticationService {
  constructor(
    private configService: ConfigService,
    private usersService: UsersService,
  ) {}

  public async registerUser(registerUserDto: RegisterUserDto) {
    // checking to see if user already exists; this function returns either null or User
    const user = await this.usersService.getUserByEmail(registerUserDto.email);

    if (!user?.hasOwnProperty("email")) {
      // TODO: SENDING VERIFICATION LINK BEFORE SAVING USER
      return this.usersService.createUser(registerUserDto);
    } else {
      throw new HttpException(
        "User with that email already exists.",
        HttpStatus.BAD_REQUEST,
      );
    }
  }

  public async getAuthenticatedUser(email: string, password: string) {
    const user = await this.usersService.getUserByEmail(email);
    // checking if user does not already exists;
    if (!user) {
      throw new HttpException(
        "Wrong credentials provided.",
        HttpStatus.BAD_REQUEST,
      );
    }
    // TODO: CHECK IF USER HAS VERIFIED HIS EMAIL
    // checking if password is correct
    const isPasswordMatching = await bcrypt.compare(password, user.password);
    if (!isPasswordMatching) {
      throw new HttpException(
        "Wrong credentials provided.",
        HttpStatus.BAD_REQUEST,
      );
    }
    return user;
  }
}
```

## Integrating authentication with Passport Local

```
npm install @nestjs/passport passport passport-local

npm install -D @types/passport-local @types/express
```

## PASSPORT STRATEGY - LOCAL

For the local strategy, Passport needs a method with a username and a password. We need to change usernameField into email.

**authentication/passport/strategies/local.strategy.ts**

```
import { Injectable } from "@nestjs/common";
import { PassportStrategy } from "@nestjs/passport";
import { Strategy } from "passport-local";
import { User } from "../../users/user.entity";
import { AuthenticationService } from "../authentication.service";

@Injectable()
export class LocalStrategy extends PassportStrategy(Strategy, "local") {
  constructor(private readonly authenticationService: AuthenticationService) {
    super({
      usernameField: "email",
    });
  }

  async validate(email: string, password: string): Promise<User> {
    return this.authenticationService.getAuthenticatedUser(email, password);
  }
}
```

Add PassportModule to AuthenticationModule's imports array. And add LocalStrategy to AuthenticationModule's providers array.

```
import { PassportModule } from "@nestjs/passport";
import { LocalStrategy } from "./passport/strategies/local.strategy";

@Module({
  imports: [PassportModule],
  providers: [LocalStrategy],
})
```

## GUARDS - AUTHORIZATION

Guards determine whether a given request will be handled by the route handler or not, depending on certain conditions.

**authentication/passport/guards/local.strategy.ts**

```
import { Injectable } from "@nestjs/common";
import { AuthGuard } from "@nestjs/passport";

@Injectable()
export class LocalAuthenticationGuard extends AuthGuard("local") {}
```

## EXTENDING REQUEST

**authentication/request-with-user.interface.ts**

Thanks to extending Request from express, login route will be handled by Passport. The data of the user is attached to the request object.
If the user authenticates successfully, we return his data. Otherwise, we throw an error.

```
import { Request } from "express";
import { User } from "src/accounts/users/user.entity";

export interface RequestWithUser extends Request {
  user: User;
}
```

## Creating controller. Controllers handle incoming requests and return responses to the client.

## INTERCEPTORS

We will use interceptors to transform the result returned from our function.
When we defined our User entity, we added Excluded decorator on the password and refreshJwtToken fields. Because we do not want to send them in a response to our frontend.

**authentication/authentication.controller.ts**

```
import {
  Body,
  ClassSerializerInterceptor,
  Controller,
  HttpCode,
  Post,
  Req,
  UseGuards,
  UseInterceptors,
} from "@nestjs/common";
import { AuthenticationService } from "./authentication.service";
import { RegisterUserDto } from "./register-user.dto";
import { RequestWithUser } from "./request-with-user.interface";
import { LocalAuthenticationGuard } from "./passport/guards/local-authentication.guard";

@UseInterceptors(ClassSerializerInterceptor)
@Controller("auth")
export class AuthenticationController {
  constructor(readonly authenticationService: AuthenticationService) {}

  @Post("register")
  async register(@Body() registerUserDto: RegisterUserDto) {
    return this.authenticationService.registerUser(registerUserDto);
  }

  @UseGuards(LocalAuthenticationGuard)
  @HttpCode(200)
  @Post("login")
  async login(@Req() request: RequestWithUser) {
    const user = request.user;
    return user;
  }
}
```

**Do not forget to add controller to AuthenticationModule's controllers array.**

## Test with Postman

## Push to Github
