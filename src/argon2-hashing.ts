import { PasswordHashingFunction } from "./authenticator";
import * as argon from "argon2";

export class Argon2HashingFunction implements PasswordHashingFunction {
  public async generateHash(password: string): Promise<string> {
    return await argon.hash(password);
  }
  public async verifyPasswordHash(
    password: string,
    passwordHash: string
  ): Promise<boolean> {
    return await argon.verify(passwordHash, password);
  }
}
