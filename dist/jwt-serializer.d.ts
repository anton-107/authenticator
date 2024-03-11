import * as jwt from "jsonwebtoken";
import { JwtPayload, Secret, SignCallback, SignOptions } from "jsonwebtoken";
import { AuthTokensSerializer } from "./authenticator";
export interface JWT {
    sign: (payload: object, secretOrPrivateKey: Secret, options: SignOptions, callback: SignCallback) => void;
    verify: (token: string, secretOrPublicKey: Secret, callback: jwt.VerifyCallback<JwtPayload | string>) => void;
}
export declare class StandardJwtImplementation implements JWT {
    sign(payload: object, secretOrPrivateKey: Secret, options: SignOptions, callback: SignCallback): void;
    verify(token: string, secretOrPublicKey: Secret, callback: jwt.VerifyCallback<JwtPayload | string>): void;
}
export interface SecretKeyProvider {
    getSecretKey(): Promise<string>;
}
export interface JWTSerializerProperties {
    jwt: JWT;
    secretKeyProvider: SecretKeyProvider;
    expiresInSeconds: number;
}
export declare class SimpleStringProvider implements SecretKeyProvider {
    private secret;
    constructor(secret: string);
    getSecretKey(): Promise<string>;
}
export declare class JWTSerializer implements AuthTokensSerializer {
    private properties;
    constructor(properties: JWTSerializerProperties);
    generateAccessToken(username: string): Promise<string>;
    decodeAccessToken(accessToken: string): Promise<string>;
}
