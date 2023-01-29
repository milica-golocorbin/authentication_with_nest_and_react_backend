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

## Push to Github

```
git add .

git commit -m "first commit"

git remote add origin https://github.com/milica-golocorbin/authentication_with_nest_and_react_backend.git

git push -u origin main
```

# Authentication API (NestJS, TypeORM, PostgreSQL, TS) - PASSPORT

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
    return await this.usersRepo.findOne({ where: { email } });
  }

  async createUser(createUserDto: CreateUserDto): Promise<User> {
    const hashedPassword = await bcrypt.hash(createUserDto.password, 10);
    const newUser = this.usersRepo.create({
      ...createUserDto,
      password: hashedPassword,
    });
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

**Do not forget to add AuthenticationModule to AppModule imports array.**

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
    const user = await this.usersService.getUserByEmail(registerUserDto.email);

    if (!user?.hasOwnProperty("email")) {
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
    if (!user) {
      throw new HttpException(
        "Wrong credentials provided.",
        HttpStatus.BAD_REQUEST,
      );
    }
    // TODO: CHECK IF USER HAS VERIFIED HIS EMAIL
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

Add PassportModule to AuthenticationModule imports array. And add LocalStrategy to AuthenticationModule providers array.

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
Applying LocalStrategy by requiring email and password from our users.

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

**Do not forget to add AuthenticationController to AuthenticationModule controllers array.**

## Test with Postman

## Push to Github

# Authentication API (NestJS, TypeORM, PostgreSQL, TS) - PASSPORT JWT

We will use JWT to restrict certain parts of the application only to authenticated users. We don’t want users to have to authenticate on every request. Instead, we will use JWT to let users indicate that they have already logged in successfully. JWT will be stored in a cookie.

JWT is a string that will be created on the server, with secret key. Thanks to that, only we will be able to decode it. We will send JWT to users, when they login. And that JWT will be sent back to the server on every request. If the token is valid, we will trust the identity of the user.

## Integrating authentication with Passport JWT

```
npm install @nestjs/jwt passport-jwt cookie-parser

npm install -D @types/passport-jwt @types/cookie-parser
```

We will add two new environment variables to .env file. We will use: **crypto.randomBytes(32).toString("hex")** to generate random key for JWT_ACCESS_TOKEN_SECRET. And we will set JWT_ACCESS_TOKEN_EXPIRATION_TIME to 1800s (30 minutes).

**.env**

```
JWT_ACCESS_TOKEN_SECRET
JWT_ACCESS_TOKEN_EXPIRATION_TIME=1800
```

**app.module.ts**

```
@Module({
  imports: [
      validationSchema: Joi.object({
        ...
        JWT_ACCESS_TOKEN_SECRET: Joi.string().required(),
        JWT_ACCESS_TOKEN_EXPIRATION_TIME: Joi.string().required(),
      }),
    }),
  ],
})
export class AppModule {}
```

## Generating Tokens

In order to create JWT we will need access to JwtService. And to get access to it, we need to add JwtModule to AuthenticationModule imports array.

**authentication/authentication.module.ts**

```
import { JwtModule } from "@nestjs/jwt";

@Module({
  imports: [JwtModule.register({})],
})
export class AuthenticationModule {}
```

**authentication/authentication.service.ts**

Add JwtService to our constructor to be able to sign the tokens.

```
import { JwtService } from "@nestjs/jwt";

@Injectable()
export class AuthenticationService {
  constructor(
    private jwtService: JwtService
  ) {}

  public createAccessToken(userId: number) {
    const payload = { userId };
    const accessToken = this.jwtService.sign(payload, {
      secret: this.configService.get("JWT_ACCESS_TOKEN_SECRET"),
      expiresIn: `${this.configService.get(
        "JWT_ACCESS_TOKEN_EXPIRATION_TIME",
      )}s`,
    });
    const cookie = `Authentication=${accessToken}; HttpOnly; Path=/; Max-Age=${this.configService.get(
      "JWT_ACCESS_TOKEN_EXPIRATION_TIME",
    )}`;

    return cookie;
  }
}
```

**authentication/authentication.controller.ts**

We need to send the token created by the createAccessToken method when user logs in successfully.

```
@UseInterceptors(ClassSerializerInterceptor)
@Controller("auth")
export class AuthenticationController {

  @UseGuards(LocalAuthenticationGuard)
  @HttpCode(200)
  @Post("login")
  async login(@Req() request: RequestWithUser) {
    const user = request.user;
    const accessTokenCookie = this.authenticationService.createAccessToken(
      user.id,
    );
    request.res.setHeader("Set-Cookie", accessTokenCookie);
    return user;
  }
}
```

## Reading Tokens

To to able to read tokens from the cookie, first we need to add **cookie-parser**.

**main.ts**

```
import * as cookieParser from "cookie-parser";

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  const configService = app.get(ConfigService);
  const port = configService.get<number>("PORT") ?? 3000;

  app.use(cookieParser());

  ...
}
bootstrap();
```

## PASSPORT STRATEGY - JWT

Reading token from the cookie header with the help of Passport JwtStrategy. When we successfully access the token, we use the id of the user that is encoded inside the cookie. With it, we can get the whole user data through the userService.getUserById method, which we will add in, after the strategy.

**authentication/passport/strategies/jwt.strategy.ts**

```
import { Request } from "express";
import { HttpException, HttpStatus, Injectable } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { PassportStrategy } from "@nestjs/passport";
import { ExtractJwt, Strategy } from "passport-jwt";
import { UsersService } from "src/accounts/users/users.service";
import { User } from "src/accounts/users/user.entity";

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy, "jwt") {
  constructor(
    private configService: ConfigService,
    private usersService: UsersService,
  ) {
    super({
      jwtFromRequest: ExtractJwt.fromExtractors([
        (request: Request) => {
          if (!request?.cookies?.Authentication) {
            throw new HttpException("Token expired.", HttpStatus.NOT_FOUND);
          }
          return request?.cookies?.Authentication;
        },
      ]),
      secretOrKey: configService.get("JWT_ACCESS_TOKEN_SECRET"),
    });
  }

  async validate(payload: { userId: number }): Promise<User> {
    const user = await this.usersService.getUserById(payload.userId);
    return user;
  }
}
```

Add JwtStrategy to AuthenticationModule providers array.

**authentication/authentication.module.ts**

```
import { JwtStrategy } from "./passport/strategies/jwt.strategy";

@Module({
  ...
  providers: [AuthenticationService, LocalStrategy, JwtStrategy],
  ...
export class AuthenticationModule {}
```

**users/users.service.ts**

```
import { HttpException, HttpStatus } from "@nestjs/common";

@Injectable()
export class UsersService {
  ...
  async getUserById(id: number) {
    const user = await this.usersRepo.findOne({ where: { id } });
    if (!user) {
      throw new HttpException("User does not exist.", HttpStatus.NOT_FOUND);
    }
    return user;
  }
```

## JWT GUARD

Applying JwtStrategy by requiring authentication from our users.

**authentication/guards/jwt-authentication.guard.ts**

```
import { Injectable } from "@nestjs/common";
import { AuthGuard } from "@nestjs/passport";

@Injectable()
export class JwtAuthenticationGuard extends AuthGuard("jwt") {}
```

## Creating log out endpoint

**authentication/authentication.controller.ts**

```
import { JwtAuthenticationGuard } from "./passport/guards/jwt-authentication.guard";

@UseInterceptors(ClassSerializerInterceptor)
@Controller("auth")
export class AuthenticationController {
  ...

  @UseGuards(JwtAuthenticationGuard)
  @HttpCode(204)
  @Post("logout")
  async logout(@Req() request: RequestWithUser) {
    request.res.setHeader("Set-Cookie", "Authentication=; HttpOnly; Path=/; Max-Age=0");
  }
}
```

## Test with Postman

## Push to Github

# Authentication API (NestJS, TypeORM, PostgreSQL, TS) - REFRESH JWT

On successful login, we will create two separate JWT tokens. One is an access token, valid for 30 minutes. The other is a refresh token that has an expiry of one week.
Both tokens will be placed in a cookie. Access token is for authentication, while making requests. Once the API states that the access token has expired, the user needs to perform a refresh.
To refresh the token, the user needs to call a separate endpoint, called /refresh. This time, the refresh token is taken from the cookies and sent to the API. If it is valid and not expired, the user receives the new access token. Thanks to that, there is no need to provide the username and password again.
When we created User entity we added field refreshJwtToken, that can be optional. When user successfully logs in, we will save refresh token in the database, and when user logs out, we will remove it from the database.

We will add two new environment variables to .env file. We will use: **crypto.randomBytes(32).toString("hex")** to generate random key for JWT_REFRESH_TOKEN_SECRET. And we will set JWT_REFRESH_TOKEN_EXPIRATION_TIME to 604800s (7 days).

**.env**

```
JWT_REFRESH_TOKEN_SECRET
JWT_REFRESH_TOKEN_EXPIRATION_TIME=604800
```

**app.module.ts**

```
@Module({
  imports: [
      validationSchema: Joi.object({
        ...
        JWT_REFRESH_TOKEN_SECRET: Joi.string().required(),
        JWT_REFRESH_TOKEN_EXPIRATION_TIME: Joi.string().required(),
      }),
    }),
  ],
})
export class AppModule {}
```

## Generating Tokens

**authentication/authentication.service.ts**

```
  public createRefreshToken(userId: number) {
    const payload = { userId };
    const refreshToken = this.jwtService.sign(payload, {
      secret: this.configService.get("JWT_REFRESH_TOKEN_SECRET"),
      expiresIn: `${this.configService.get(
        "JWT_REFRESH_TOKEN_EXPIRATION_TIME",
      )}s`,
    });
    const cookie = `Refresh=${refreshToken}; HttpOnly; Path=/; Max-Age=${this.configService.get(
      "JWT_REFRESH_TOKEN_EXPIRATION_TIME",
    )}`;
    return { cookie, refreshToken };
  }
```

## Saving refresh token in database

Before going into the controller and changing the login function to include our refresh token, as well, on successful login, we will add new method to UsersService. This method will hash refresh token created by our AuthenticationService, and save it to the database.

**users/users.service.ts**

```
  async saveRefreshToken(refreshToken: string, userId: number) {
    const hashedRefreshToken = await bcrypt.hash(refreshToken, 10);
    return await this.usersRepo.update(userId, {
      refreshJwtToken: hashedRefreshToken,
    });
  }
```

**authentication/authentication.controller.ts**

We have to add UsersService to constructor.

```
import { UsersService } from "../users/users.service";

@UseInterceptors(ClassSerializerInterceptor)
@Controller("auth")
export class AuthenticationController {
  constructor(
  readonly authenticationService: AuthenticationService,
  readonly usersService: UsersService,
  ) {}

  @UseGuards(LocalAuthenticationGuard)
  @HttpCode(200)
  @Post("login")
  async login(@Req() request: RequestWithUser) {
    const user = request.user;
    const accessTokenCookie = this.authenticationService.createAccessToken(
      user.id,
    );
    const { cookie: refreshTokenCookie, refreshToken } =
      this.authenticationService.createRefreshToken(user.id);
    await this.usersService.saveRefreshToken(refreshToken, user.id);
    request.res.setHeader("Set-Cookie", [
      accessTokenCookie,
      refreshTokenCookie,
    ]);
    return user;
  }
```

## Reading Tokens

## PASSPORT STRATEGY - REFRESH JWT

Reading token from the cookie header with the help of Passport JwtRefreshStrategy. When we successfully access the token, we use the id of the user that is encoded inside the cookie. With it, we can get the whole user data through the userService.getUserByRefreshToken method, which we will add in, after the strategy.

**authentication/passport/strategies/jwt-refresh.strategy.ts**

```
import { Request } from "express";
import { HttpException, HttpStatus, Injectable } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { UsersService } from "src/accounts/users/users.service";
import { PassportStrategy } from "@nestjs/passport";
import { ExtractJwt, Strategy } from "passport-jwt";
import { User } from "../../../users/user.entity";

@Injectable()
export class JwtRefreshTokenStrategy extends PassportStrategy(
  Strategy,
  "jwt-refresh-token",
) {
  constructor(
    private configService: ConfigService,
    private usersService: UsersService,
  ) {
    super({
      jwtFromRequest: ExtractJwt.fromExtractors([
        (request: Request) => {
          if (!request?.cookies?.Refresh) {
            throw new HttpException("Token expired.", HttpStatus.NOT_FOUND);
          }
          return request?.cookies?.Refresh;
        },
      ]),
      secretOrKey: configService.get("JWT_REFRESH_TOKEN_SECRET"),
      passReqToCallback: true,
    });
  }

  async validate(request: Request, payload: { userId: number }): Promise<User> {
    const refreshToken = request.cookies?.Refresh;
    const user = await this.usersService.getUserByRefreshToken(
      refreshToken,
      payload.userId,
    );
    return user;
  }
}
```

Add JwtRefreshTokenStrategy to AuthenticationModule providers array.

**authentication/authentication.module.ts**

```
import { JwtRefreshTokenStrategy } from "./passport/strategies/jwt-refresh.strategy";

@Module({
  ...
  providers: [AuthenticationService, LocalStrategy, JwtStrategy, JwtRefreshTokenStrategy],
  ...
export class AuthenticationModule {}
```

**users/users.service.ts**

```
import { HttpException, HttpStatus, Injectable } from "@nestjs/common";
import { InjectRepository } from "@nestjs/typeorm";
import { Repository } from "typeorm";
import { User } from "./user.entity";
import { CreateUserDto } from "./create-user.dto";
import * as bcrypt from "bcrypt";

@Injectable()
export class UsersService {
  ...
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
}
```

## JWT REFRESH GUARD

Applying JwtRefreshTokenStrategy by requiring refresh token from our users.

**authentication/guards/jwt-refresh-authentication.guard.ts**

```
import { Injectable } from "@nestjs/common";
import { AuthGuard } from "@nestjs/passport";

@Injectable()
export class JwtRefreshAuthenticationGuard extends AuthGuard(
  "jwt-refresh-token",
) {}
```

## Creating refresh endpoint

**authentication/authentication.controller.ts**

```
import { Get } from "@nestjs/common";
import { JwtRefreshAuthenticationGuard } from "./passport/guards/jwt-refresh-authentication.guard";

@UseInterceptors(ClassSerializerInterceptor)
@Controller("auth")
export class AuthenticationController {
  ...
  @UseGuards(JwtRefreshAuthenticationGuard)
  @Get("refresh")
  refresh(@Req() request: RequestWithUser) {
    const accessTokenCookie = this.authenticationService.createAccessToken(
      request.user.id,
    );
    request.res.setHeader("Set-Cookie", accessTokenCookie);
    return request.user;
  }
}
```

## Changing logout function in controller

We will add after removeRefreshToken to our UsersService, that will clear refreshJwtToken from the database.

**authentication/authentication.controller.ts**

```
@UseInterceptors(ClassSerializerInterceptor)
@Controller("auth")
export class AuthenticationController {
  ...
  @UseGuards(JwtAuthenticationGuard)
  @HttpCode(204)
  @Post("logout")
  async logout(@Req() request: RequestWithUser) {
    await this.usersService.removeRefreshToken(request.user.id);
    request.res.setHeader("Set-Cookie", [
      "Authentication=; HttpOnly; Path=/; Max-Age=0",
      "Refresh=; HttpOnly; Path=/; Max-Age=0",
    ]);
  }
```

**users/users.service.ts**

```
@Injectable()
export class UsersService {
  ...
  async removeRefreshToken(userId: number) {
    return await this.usersRepo.update(userId, {
      refreshJwtToken: null,
    });
  }
}
```

## Test with Postman

Change the JWT_ACCESS_TOKEN_EXPIRATION_TIME and JWT_REFRESH_TOKEN_EXPIRATION_TIME for testing to see Passport strategies in action.

## Push to Github

# Authentication API (NestJS, TypeORM, PostgreSQL, TS) - NODEMAILER

**EMAIL**

Create email folder inside the accounts folder.
We will use Nodemailer for sending emails. Check this StackOverflow post for: [enabling less secure app access with Google, when using Nodemailer](https://stackoverflow.com/questions/72530276/how-to-send-emails-with-google-using-nodemailer-after-google-disabled-less-sure).

```
npm install nodemailer

npm install -D @types/nodemailer
```

We will three new environment variables provided by gmail, when you enable less secure apps.

**.env**

```
EMAIL_SERVICE=gmail
EMAIL_USER
EMAIL_PASSWORD
```

**app.module.ts**

```
@Module({
  imports: [
      validationSchema: Joi.object({
        ...
        EMAIL_SERVICE: Joi.string().required(),
        EMAIL_USER: Joi.string().required(),
        EMAIL_PASSWORD: Joi.string().required(),
      }),
    }),
  ],
})
export class AppModule {}
```

## Nodemailer set up

We will set up NodemailerModule as dynamic module. What we used so far, with modules we created were static modules.
We need dynamic module, because we want NodemailerModule to be customized by consuming modules. First one being EmailVerificationModule.
Great explanation can be found in NestJs documentation: [Dynamic module](https://docs.nestjs.com/fundamentals/dynamic-modules#dynamic-module-use-case).
We will follow [Configurable module builder](https://docs.nestjs.com/fundamentals/dynamic-modules#configurable-module-builder) when building our dynamic module.

**email/nodemailer-options.interface**

```
export interface NodemailerOptionsInterface {
  service: string;
  user: string;
  password: string;
}
```

**nodemailer.module-definition.ts**

```
import { ConfigurableModuleBuilder } from "@nestjs/common";
import { NodemailerOptionsInterface } from "./nodemailer-options.interface";

export const {
  ConfigurableModuleClass: ConfigurableEmailModule,
  MODULE_OPTIONS_TOKEN: EMAIL_CONFIG_OPTIONS,
} = new ConfigurableModuleBuilder<NodemailerOptionsInterface>().build();
```

**nodemailer.module.ts**

```
import { Module } from "@nestjs/common";
import { ConfigurableEmailModule } from "./nodemailer.module-definition";
import { NodemailerService } from "./nodemailer.service";

@Module({
  providers: [NodemailerService],
  exports: [NodemailerService],
})
export class NodemailerModule extends ConfigurableEmailModule {}
```

**nodemailer.service.ts**

```
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
```

## Email verification

To check if we have properly added everything for Nodemailer, we will try our dynamic configuration, by creating first consumer EmailVerificationModule.

**email/email-verification.module.ts**

```
import { Module } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { NodemailerModule } from "./nodemailer.module";

@Module({
  imports: [
    NodemailerModule.registerAsync({
      inject: [ConfigService],
      useFactory: (configService: ConfigService) => ({
        service: configService.get("EMAIL_SERVICE"),
        user: configService.get("EMAIL_USER"),
        password: configService.get("EMAIL_PASSWORD"),
      }),
    }),
  ],
})
export class EmailVerificationModule {}
```

**Do not forget to add EmailVerificationModule to AuthenticationModule import array.**

## Push to Github

# Authentication API (NestJS, TypeORM, PostgreSQL, TS) - EMAIL VERIFICATION

When we created User entity, we added isVerified field and set it to false by default.
When user enters his details for registration, we will return user a message, an URL containing the JWT. In order to proceed with logging in process, user need to visit email address and open link we sent.
To do that, we will add three new environment variables to .env file. We will use: **crypto.randomBytes(32).toString("hex")** to generate random key for JWT_VERIFICATION_TOKEN_SECRET. We will set JWT_VERIFICATION_TOKEN_EXPIRATION_TIME to 21600s (6 days). And we will set EMAIL_VERIFICATION_URL to our frontend route.

**.env**

```
JWT_VERIFICATION_TOKEN_SECRET
JWT_VERIFICATION_TOKEN_EXPIRATION_TIME=21600 #6h
EMAIL_VERIFICATION_URL=http://localhost:5173/auth/verify-email
```

**app.module.ts**

```
@Module({
  imports: [
      validationSchema: Joi.object({
        ...
        JWT_VERIFICATION_TOKEN_SECRET: Joi.string().required(),
        JWT_VERIFICATION_TOKEN_EXPIRATION_TIME: Joi.string().required(),
        EMAIL_VERIFICATION_URL: Joi.string().required(),
      }),
    }),
  ],
})
export class AppModule {}
```

## Send verification link

In previous blog we added EmailVerificationModule to check if we connected everything properly with Nodemailer. Now we'll create EmailVerificationService and add method for sending emails.

**email-verification.service.ts**

```
import { Injectable } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { JwtService } from "@nestjs/jwt";
import { NodemailerService } from "./nodemailer.service";

@Injectable()
export class EmailVerificationService {
  constructor(
    private configService: ConfigService,
    private nodemailerService: NodemailerService,
    private jwtService: JwtService,
  ) {}

  public sendVerificationLink(email: string) {
    const payload = { email };

    const token = this.jwtService.sign(payload, {
      secret: this.configService.get("JWT_VERIFICATION_TOKEN_SECRET"),
      expiresIn: `${this.configService.get(
        "JWT_VERIFICATION_TOKEN_EXPIRATION_TIME",
      )}s`,
    });

    const url = `${this.configService.get(
      "EMAIL_VERIFICATION_URL",
    )}?token=${token}`;

    const text = `Welcome to the application. To confirm the email address, click here: ${url}`;

    return this.nodemailerService.sendMail({
      to: email,
      subject: "Email Verification",
      text,
    });
  }
}
```

**email/email-verification.module.ts**

```
import { JwtModule } from "@nestjs/jwt";
import { EmailVerificationService } from "./email-verification.service";

@Module({
  imports: [JwtModule.register({})],
  providers: [EmailVerificationService],
  exports: [EmailVerificationService],
})
export class EmailVerificationModule {}
```

**authentication/authentication.controller.ts**

We'll modify our register method.

```
import { EmailVerificationService } from "./../email/email-verification.service";

@UseInterceptors(ClassSerializerInterceptor)
@Controller("auth")
export class AuthenticationController {
  constructor(
    readonly emailVerificationService: EmailVerificationService,
  ) {}

  @Post("register")
  async register(@Body() registerUserDto: RegisterUserDto) {
    const user = await this.authenticationService.registerUser(registerUserDto);
    await this.emailVerificationService.sendVerificationLink(
      registerUserDto.email,
    );
    return { user, message: "Visit email to verify your account." };
  }
```

# Confirming email address

When user clicks on the link from the email, our frontend application needs to get the token from the URL and send it to our API. For that, we need to create a new controller.

**email/email-verification.controller.ts**

```
import { Controller } from "@nestjs/common/decorators";
import { EmailVerificationService } from "./email-verification.service";

@Controller("email-verification")
export class EmailVerificationController {
  readonly emailVerificationService: EmailVerificationService;
}
```

**Do not forget to add EmailVerificationController to EmailVerificationModule controllers array.**

## Push to Github
