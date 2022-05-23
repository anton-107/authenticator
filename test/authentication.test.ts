import { Argon2HashingFunction } from "../src/argon2-hashing";
import { Authenticator, User, UserStore } from "../src/authenticator";

class TestUserStore implements UserStore {
  private users: User[] = [];

  public async getUserByName(username: string): Promise<User | null> {
    return this.users.find((u) => u.username === username);
  }
  public async addUser(user: User): Promise<void> {
    this.users.push(user);
  }
}
const userStore = new TestUserStore();
const passwordHashingFunction = new Argon2HashingFunction();

describe("authentication", () => {
  beforeAll(async () => {
    const a = new Authenticator({ userStore, passwordHashingFunction });
    await a.addUser("user1", "1234");
  });
  it("should hash user password on sign up and verify the password on sign in", async () => {
    const a = new Authenticator({ userStore, passwordHashingFunction });
    await a.addUser("user2", "some-random-password");
    const u = await userStore.getUserByName("user2");
    expect(u.passwordHash).toContain("$argon2i$v=19$m=4096");
    const user = a.signIn("user2", "some-random-password");
    expect((await user).isAuthenticated).toBe(true);
  });
  it("should not sign in a user coming with a non-existent username", async () => {
    const a = new Authenticator({ userStore, passwordHashingFunction });
    const user = await a.signIn("user0", "1234");
    expect(user.isAuthenticated).toBe(false);
  });
  it("should sign in a user coming with a correct password", async () => {
    const a = new Authenticator({ userStore, passwordHashingFunction });
    const user = await a.signIn("user1", "1234");
    expect(user.isAuthenticated).toBe(true);
  });
  it("should not sign in a user coming with an incorrect password", async () => {
    const a = new Authenticator({ userStore, passwordHashingFunction });
    const user = await a.signIn("user1", "5678");
    expect(user.isAuthenticated).toBe(false);
  });
  it("should authenticate a valid user token for user1", async () => {
    const a = new Authenticator({ userStore, passwordHashingFunction });
    const user = await a.authenticate("usertoken sample-user-token:user1");
    expect(user.isAuthenticated).toBe(true);
    expect(user.username).toBe("user1");
  });
  it("should authenticate a valid user token for user2", async () => {
    const a = new Authenticator({ userStore, passwordHashingFunction });
    const user = await a.authenticate("usertoken sample-user-token:user2");
    expect(user.isAuthenticated).toBe(true);
    expect(user.username).toBe("user2");
  });
  it("should not authenticate a user with an unsupported token type", async () => {
    const a = new Authenticator({ userStore, passwordHashingFunction });
    const r = await a.authenticate("username sample-user-token:user2");
    expect(r.isAuthenticated).toBe(false);
    expect(r.errorMessage).toBe("Token type is not supported");
  });
  it("should not authenticate a user with an empty token ", async () => {
    const a = new Authenticator({ userStore, passwordHashingFunction });
    const r = await a.authenticate("usertoken");
    expect(r.isAuthenticated).toBe(false);
    expect(r.errorMessage).toBe("Empty token payload");
  });
  it("should not authenticate a user with an invalid token ", async () => {
    const a = new Authenticator({ userStore, passwordHashingFunction });
    const r = await a.authenticate("usertoken some-invalid-token");
    expect(r.isAuthenticated).toBe(false);
    expect(r.errorMessage).toBe("Invalid token payload");
  });
  it("should not authenticate a user when hash verification failse", async () => {
    const a = new Authenticator({
      userStore,
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
