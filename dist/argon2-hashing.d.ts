import { PasswordHashingFunction } from "./authenticator";
export declare class Argon2HashingFunction implements PasswordHashingFunction {
  generateHash(password: string): Promise<string>;
  verifyPasswordHash(password: string, passwordHash: string): Promise<boolean>;
}
