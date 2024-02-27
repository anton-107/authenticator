import * as jwt from "jsonwebtoken";
import { JwtPayload, Secret, SignCallback, SignOptions } from "jsonwebtoken";

import { AuthTokensSerializer } from "./authenticator";

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
      throw Error("Secret key provider error");
    }

    return new Promise((resolve, reject) => {
      this.properties.jwt.sign(
        { username },
        secretKey,
        { expiresIn: 15 * 60 },
        (err, token) => {
          if (err) {
            return reject("jwt signing failed");
          }
          if (token === undefined) {
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
      throw "Secret key provider error";
    }

    return new Promise((resolve, reject) => {
      this.properties.jwt.verify(accessToken, secretKey, (err, payload) => {
        if (err) {
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
