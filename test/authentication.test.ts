import { Argon2HashingFunction } from "../src/argon2-hashing";
import { ScryptHashingFunction } from "../src/scrypt-hashing";
import {
  Authenticator,
  PasswordHashingFunction,
  User,
  UserStore,
} from "../src/authenticator";
import {
  JWTSerializer,
  StandardJwtImplementation,
} from "../src/jwt-serializer";

class TestUserStore implements UserStore {
  private users: User[] = [];

  public async getUserByName(username: string): Promise<User | null> {
    return this.users.find((u) => u.username === username) || null;
  }
  public async addUser(user: User): Promise<void> {
    this.users.push(user);
  }
}
const authTokensSerializer = new JWTSerializer(
  new StandardJwtImplementation(),
  "some-secret-key"
);

const hashingFunctions: { [name: string]: PasswordHashingFunction } = {
  argon: new Argon2HashingFunction(),
  scrypt: new ScryptHashingFunction(),
};

Object.keys(hashingFunctions).forEach((k) => {
  const passwordHashingFunction = hashingFunctions[k];
  const userStore = new TestUserStore();

  describe(`authentication using ${k} as hashing mechanism`, () => {
    beforeAll(async () => {
      const a = new Authenticator({
        userStore,
        passwordHashingFunction,
        authTokensSerializer,
      });
      await a.addUser("user1", "1234");
    });
    it("should hash user password on sign up and verify the password on sign in and authenticate user toke", async () => {
      const a = new Authenticator({
        userStore,
        passwordHashingFunction,
        authTokensSerializer,
      });
      await a.addUser("user2", "some-random-password");
      const u = await userStore.getUserByName("user2");
      expect(u).not.toBeNull();
      expect((u as User).passwordHash.length).toBeGreaterThan(0);
      const user = await a.signIn("user2", "some-random-password");
      expect(user.isAuthenticated).toBe(true);
      expect(user.accessToken).toBeTruthy();
      expect(user.accessToken).toContain("jwt ");
      expect(user.accessToken).not.toBeUndefined();
      const authResult = await a.authenticate(user.accessToken as string);
      expect(authResult.isAuthenticated).toBe(true);
      expect(authResult.username).toBe("user2");
    });
    it("should not sign in a user coming with a non-existent username", async () => {
      const a = new Authenticator({
        userStore,
        passwordHashingFunction,
        authTokensSerializer,
      });
      const user = await a.signIn("user0", "1234");
      expect(user.isAuthenticated).toBe(false);
    });
    it("should sign in a user coming with a correct password", async () => {
      const a = new Authenticator({
        userStore,
        passwordHashingFunction,
        authTokensSerializer,
      });
      const user = await a.signIn("user1", "1234");
      expect(user.isAuthenticated).toBe(true);
    });
    it("should not sign in a user coming with an incorrect password", async () => {
      const a = new Authenticator({
        userStore,
        passwordHashingFunction,
        authTokensSerializer,
      });
      const user = await a.signIn("user1", "5678");
      expect(user.isAuthenticated).toBe(false);
    });
    it("should authenticate a valid user token for user1", async () => {
      const a = new Authenticator({
        userStore,
        passwordHashingFunction,
        authTokensSerializer,
      });
      const signIn = await a.signIn("user1", "1234");
      expect(signIn.isAuthenticated).toBe(true);
      expect(signIn.accessToken).not.toBeUndefined();
      const user = await a.authenticate(signIn.accessToken as string);
      expect(user.isAuthenticated).toBe(true);
      expect(user.username).toBe("user1");
    });
    it("should authenticate a valid user token for user2", async () => {
      const a = new Authenticator({
        userStore,
        passwordHashingFunction,
        authTokensSerializer,
      });
      const signIn = await a.signIn("user2", "some-random-password");
      expect(signIn.accessToken).not.toBeUndefined();
      const user = await a.authenticate(signIn.accessToken as string);
      expect(user.isAuthenticated).toBe(true);
      expect(user.username).toBe("user2");
    });
    it("should not authenticate a user with an unsupported token type", async () => {
      const a = new Authenticator({
        userStore,
        passwordHashingFunction,
        authTokensSerializer,
      });
      const r = await a.authenticate("username sample-user-token:user2");
      expect(r.isAuthenticated).toBe(false);
      expect(r.errorMessage).toBe("Token type is not supported");
    });
    it("should not authenticate a user with an empty token ", async () => {
      const a = new Authenticator({
        userStore,
        passwordHashingFunction,
        authTokensSerializer,
      });
      const r = await a.authenticate("jwt");
      expect(r.isAuthenticated).toBe(false);
      expect(r.errorMessage).toBe("Empty token payload");
    });
    it("should not authenticate a user with an invalid token ", async () => {
      const a = new Authenticator({
        userStore,
        passwordHashingFunction,
        authTokensSerializer,
      });
      const r = await a.authenticate("jwt some-invalid-token");
      expect(r.isAuthenticated).toBe(false);
      expect(r.errorMessage).toBe("Invalid token payload");
    });
    it("should not authenticate a user when hash verification fails", async () => {
      const a = new Authenticator({
        userStore,
        authTokensSerializer,
        passwordHashingFunction: {
          async generateHash() {
            return "hash";
          },
          async verifyPasswordHash(): Promise<boolean> {
            throw Error("This method intentionally throws an error");
          },
        },
      });
      const user = await a.signIn("user1", "1234");
      expect(user.isAuthenticated).toBe(false);
    });
  });
});
