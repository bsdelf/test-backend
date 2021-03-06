import { Dialect } from 'sequelize';

export interface LoggerProviderConfig {
  level?: string;
  enabled: boolean;
  pretty: boolean;
  file: string | null;
}

export interface RedisProviderConfig {
  host: string;
  port: number;
  keyPrefix: string;
}

export interface SequelizeProviderConfig {
  dialect: Dialect;
  host: string;
  username: string;
  password?: string;
  database: string;
  logging: boolean;
}

export interface HttpApplicationConfig {
  address: string;
  port: number;
  jwt: {
    secret: string;
  };
}

export interface Config {
  providers: {
    logger: LoggerProviderConfig;
    redis: RedisProviderConfig;
    sequelize: SequelizeProviderConfig;
  };
  applications: {
    http: HttpApplicationConfig;
  };
}
