import { AuthTokensSerializer } from "./authenticator";
import * as jwt from "jsonwebtoken";

export class JWTSerializer implements AuthTokensSerializer {
  constructor(private secretKey: string) {}
  public async generateAccessToken(username: string): Promise<string> {
    return new Promise((resolve) => {
      jwt.sign(
        { username },
        this.secretKey,
        { expiresIn: 15 * 60 },
        (err, token) => {
          console.log("jwt sign result", err);
          resolve(token);
        }
      );
    });
  }
  public async decodeAccessToken(accessToken: string): Promise<string> {
    return new Promise((resolve, reject) => {
      jwt.verify(accessToken, this.secretKey, (err, payload) => {
        if (err) {
          console.error("Error decoding token", err);
          return reject("Invalid token payload");
        }
        resolve(payload["username"]);
      });
    });
  }
}
