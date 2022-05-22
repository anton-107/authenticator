import { RuntimeError } from "./runtime-error";

interface SigninResult {
  isAuthenticated: boolean;
}

interface AuthenticationResult {
  isAuthenticated: boolean;
  username?: string;
  errorMessage?: string;
}

export interface User {
  username: string;
  passwordHash: string;
}

export interface UserStore {
  getUserByName(username: string): Promise<User | null>;
}

interface AuthenticatorProperties {
  userStore: UserStore;
}

export class Authenticator {
  constructor(private props: AuthenticatorProperties) {}
  public async signIn(
    username: string,
    password: string
  ): Promise<SigninResult> {
    const user = await this.props.userStore.getUserByName(username);
    const isAuthenticated = user !== null && user.passwordHash === password;
    return {
      isAuthenticated,
    };
  }
  public authenticate(userToken: string): AuthenticationResult {
    try {
      const username = this.readToken(userToken);
      return {
        isAuthenticated: true,
        username,
      };
    } catch (err) {
      return {
        isAuthenticated: false,
        errorMessage: String(err),
      };
    }
  }
  private readToken(userToken): string {
    const [tokenType, token] = userToken.split(" ");
    if (tokenType !== "usertoken") {
      throw new RuntimeError("Token type is not supported", { tokenType });
    }
    if (!token || token.length === 0) {
      throw new RuntimeError("Empty token payload", { token });
    }
    const parts = token.split(":");
    if (parts.length !== 2) {
      throw new RuntimeError("Invalid token payload", { token });
    }
    return parts[1];
  }
}
