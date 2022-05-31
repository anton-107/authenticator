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
export declare class StandardJwtImplementation implements JWT {
  sign(
    payload: object,
    secretOrPrivateKey: Secret,
    options: SignOptions,
    callback: SignCallback
  ): void;
  verify(
    token: string,
    secretOrPublicKey: Secret,
    callback: jwt.VerifyCallback<JwtPayload | string>
  ): void;
}
export declare class JWTSerializer implements AuthTokensSerializer {
  private jwt;
  private secretKey;
  constructor(jwt: JWT, secretKey: string);
  generateAccessToken(username: string): Promise<string>;
  decodeAccessToken(accessToken: string): Promise<string>;
}
