import { RuntimeError } from "./runtime-error";

interface SigninResult {
  isAuthenticated: boolean;
  accessToken?: string;
  authenticationFailedReason?: string;
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
  addUser(user: User): Promise<void>;
}

export interface PasswordHashingFunction {
  generateHash(password: string): Promise<string>;
  verifyPasswordHash(password: string, passwordHash: string): Promise<boolean>;
}

export interface AuthTokensSerializer {
  generateAccessToken(username: string): Promise<string>;
  decodeAccessToken(accessToken: string): Promise<string>;
}

interface AuthenticatorProperties {
  userStore: UserStore;
  passwordHashingFunction: PasswordHashingFunction;
  authTokensSerializer: AuthTokensSerializer;
}

export class Authenticator {
  constructor(private props: AuthenticatorProperties) {}
  public async addUser(username: string, password: string): Promise<void> {
    this.props.userStore.addUser({
      username,
      passwordHash: await this.props.passwordHashingFunction.generateHash(
        password
      ),
    });
  }
  public async signIn(
    username: string,
    password: string
  ): Promise<SigninResult> {
    const user = await this.props.userStore.getUserByName(username);
    if (!user) {
      return {
        isAuthenticated: false,
        authenticationFailedReason: `User with name '${username}' is not found`,
      };
    }
    try {
      const isAuthenticated =
        await this.props.passwordHashingFunction.verifyPasswordHash(
          password,
          user.passwordHash
        );
      if (!isAuthenticated) {
        return {
          isAuthenticated: false,
          authenticationFailedReason: `User '${username}' is found, but the given password of length(${password.length}) is incorrect`,
        };
      }
      const accessToken =
        await this.props.authTokensSerializer.generateAccessToken(username);
      return {
        isAuthenticated: true,
        accessToken: `jwt ${accessToken}`,
      };
    } catch (err) {
      return {
        isAuthenticated: false,
      };
    }
  }
  public async authenticate(
    accessToken: string
  ): Promise<AuthenticationResult> {
    try {
      const username = await this.readToken(accessToken);
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
  private async readToken(accessToken: string): Promise<string> {
    const [tokenType, token] = accessToken.split(" ");
    if (tokenType !== "jwt") {
      throw new RuntimeError("Token type is not supported", { tokenType });
    }
    if (!token || token.length === 0) {
      throw new RuntimeError("Empty token payload", { token });
    }
    return await this.props.authTokensSerializer.decodeAccessToken(token);
  }
}
