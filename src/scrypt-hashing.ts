import { randomBytes, scrypt } from "crypto";

import { PasswordHashingFunction } from "./authenticator";

export function handleError(
  message: string,
  error: Error | null,
  reject: (message: string) => void
) {
  if (error === null) {
    return;
  }
  reject(`Error: ${message}: ${error}`);
}

export class ScryptHashingFunction implements PasswordHashingFunction {
  generateHash(password: string): Promise<string> {
    return new Promise((resolve, reject) => {
      const salt = randomBytes(128).toString("hex");
      scrypt(password, salt, 64, (err, key) => {
        handleError("Error generating scrypt hash", err, reject);
        resolve(`${salt}.${key.toString("hex")}`);
      });
    });
  }
  verifyPasswordHash(password: string, passwordHash: string): Promise<boolean> {
    return new Promise((resolve, reject) => {
      const parts = passwordHash.split(".");
      if (parts.length !== 2) {
        return reject(`Error getting salt from hash: ${passwordHash}`);
      }
      const salt = parts[0];
      const hash = parts[1];
      scrypt(password, salt, 64, (err, key) => {
        handleError("Error generating scrypt hash", err, reject);
        if (hash !== key.toString("hex")) {
          return resolve(false);
        }
        resolve(true);
      });
    });
  }
}
