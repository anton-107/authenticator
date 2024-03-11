export interface SigninResult {
  isAuthenticated: boolean;
  accessToken?: string;
  authenticationFailedReason?: string;
}
export interface AuthenticationResult {
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
export declare class Authenticator {
  private props;
  constructor(props: AuthenticatorProperties);
  addUser(username: string, password: string): Promise<void>;
  signIn(username: string, password: string): Promise<SigninResult>;
  authenticate(accessToken: string): Promise<AuthenticationResult>;
  private readToken;
}
export {};
