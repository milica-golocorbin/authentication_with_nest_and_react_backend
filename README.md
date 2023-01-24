# Authentication API (NestJS, TypeORM, PostgreSQL, TS) - Part 01

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
