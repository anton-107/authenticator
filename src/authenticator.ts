interface AuthenticationResult {
  isAuthenticated: boolean;
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
  public async authenticate(
    username: string,
    password: string
  ): Promise<AuthenticationResult> {
    const user = await this.props.userStore.getUserByName(username);
    return {
      isAuthenticated: user !== null && user.passwordHash === password,
    };
  }
}
