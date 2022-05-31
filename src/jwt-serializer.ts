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

export class JWTSerializer implements AuthTokensSerializer {
  constructor(private jwt: JWT, private secretKey: string) {}
  public async generateAccessToken(username: string): Promise<string> {
    return new Promise((resolve, reject) => {
      this.jwt.sign(
        { username },
        this.secretKey,
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
    return new Promise((resolve, reject) => {
      this.jwt.verify(accessToken, this.secretKey, (err, payload) => {
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
