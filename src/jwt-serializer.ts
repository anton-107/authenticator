import { AuthTokensSerializer } from "./authenticator";
import * as jwt from "jsonwebtoken";
import { JwtPayload, Secret, SignCallback, SignOptions } from "jsonwebtoken";

export interface JWT {
  sign: (
    payload: object,
    secretOrPrivateKey: Secret,
    options: SignOptions,
    callback: SignCallback
  ) => void;
  verify: (
    token: string,
    secretOrPublicKey: Secret,
    callback: jwt.VerifyCallback<JwtPayload | string>
  ) => void;
}

export class StandardJwtImplementation implements JWT {
  public sign(
    payload: object,
    secretOrPrivateKey: Secret,
    options: SignOptions,
    callback: SignCallback
  ): void {
    return jwt.sign(payload, secretOrPrivateKey, options, callback);
  }
  public verify(
    token: string,
    secretOrPublicKey: Secret,
    callback: jwt.VerifyCallback<JwtPayload | string>
  ): void {
    return jwt.verify(token, secretOrPublicKey, callback);
  }
}

export interface SecretKeyProvider {
  getSecretKey(): Promise<string>;
}

export interface JWTSerializerProperties {
  jwt: JWT;
  secretKeyProvider: SecretKeyProvider;
}

export class SimpleStringProvider implements SecretKeyProvider {
  constructor(private secret: string) {}
  public async getSecretKey(): Promise<string> {
    return this.secret;
  }
}

export class JWTSerializer implements AuthTokensSerializer {
  constructor(private properties: JWTSerializerProperties) {}
  public async generateAccessToken(username: string): Promise<string> {
    let secretKey = "";
    try {
      secretKey = await this.properties.secretKeyProvider.getSecretKey();
    } catch (err) {
      console.error("Secret key provider error", err);
      throw "Secret key provider error";
    }

    return new Promise((resolve, reject) => {
      this.properties.jwt.sign(
        { username },
        secretKey,
        { expiresIn: 15 * 60 },
        (err, token) => {
          if (err) {
            console.error("jwt sign result error", err);
            return reject("jwt signing failed");
          }
          if (token === undefined) {
            console.error("jwt sign returned undefined string");
            return reject("jwt signing failed");
          }
          return resolve(token);
        }
      );
    });
  }
  public async decodeAccessToken(accessToken: string): Promise<string> {
    let secretKey = "";
    try {
      secretKey = await this.properties.secretKeyProvider.getSecretKey();
    } catch (err) {
      console.error("Secret key provider error", err);
      throw "Secret key provider error";
    }

    return new Promise((resolve, reject) => {
      this.properties.jwt.verify(accessToken, secretKey, (err, payload) => {
        if (err) {
          console.error("Error decoding token", err);
          return reject("Invalid token payload");
        }
        if (!payload) {
          return reject("Empty payload");
        }
        if (!(payload as JwtPayload)["username"]) {
          return reject("No username in payload");
        }
        resolve((payload as JwtPayload)["username"]);
      });
    });
  }
}
