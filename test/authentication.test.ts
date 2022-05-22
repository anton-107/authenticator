import { Authenticator, User, UserStore } from "../src/authenticator";

class TestUserStore implements UserStore {
  public getUserByName(username: string): Promise<User | null> {
    return Promise.resolve(this.getTestUser(username));
  }
  private getTestUser(username: string): User | null {
    switch (username) {
      case "user1":
        return {
          username: "user1",
          passwordHash: "1234",
        };
      default:
        return null;
    }
  }
}
const userStore = new TestUserStore();

describe("authentication", () => {
  it("should not sign in a user coming with a non-existent username", async () => {
    const a = new Authenticator({ userStore });
    const user = await a.signIn("user0", "1234");
    expect(user.isAuthenticated).toBe(false);
  });
  it("should sign in a user coming with a correct password", async () => {
    const a = new Authenticator({ userStore });
    const user = await a.signIn("user1", "1234");
    expect(user.isAuthenticated).toBe(true);
  });
  it("should not sign in a user coming with an incorrect password", async () => {
    const a = new Authenticator({ userStore });
    const user = await a.signIn("user1", "5678");
    expect(user.isAuthenticated).toBe(false);
  });
  it("should authenticate a valid user token for user1", async () => {
    const a = new Authenticator({ userStore });
    const user = await a.authenticate("usertoken sample-user-token:user1");
    expect(user.isAuthenticated).toBe(true);
    expect(user.username).toBe("user1");
  });
  it("should authenticate a valid user token for user2", async () => {
    const a = new Authenticator({ userStore });
    const user = await a.authenticate("usertoken sample-user-token:user2");
    expect(user.isAuthenticated).toBe(true);
    expect(user.username).toBe("user2");
  });
  it("should not authenticate a user with an unsupported token type", async () => {
    const a = new Authenticator({ userStore });
    const r = await a.authenticate("username sample-user-token:user2");
    expect(r.isAuthenticated).toBe(false);
    expect(r.errorMessage).toBe("Token type is not supported");
  });
  it("should not authenticate a user with an empty token ", async () => {
    const a = new Authenticator({ userStore });
    const r = await a.authenticate("usertoken");
    expect(r.isAuthenticated).toBe(false);
    expect(r.errorMessage).toBe("Empty token payload");
  });
  it("should not authenticate a user with an invalid token ", async () => {
    const a = new Authenticator({ userStore });
    const r = await a.authenticate("usertoken some-invalid-token");
    expect(r.isAuthenticated).toBe(false);
    expect(r.errorMessage).toBe("Invalid token payload");
  });
});
