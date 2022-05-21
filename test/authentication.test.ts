import { Authenticator, User, UserStore } from "../src/authenticator";

class TestUserStore implements UserStore {
  public getUserByName(username: string): Promise<User | null> {
    return Promise.resolve(this.getTestUser(username));
  }
  private getTestUser(username: string): User | null {
    switch(username) {
      case 'user1':
        return {
          username: 'user1',
          passwordHash: '1234',
        };
      default:
        return null;
    }
  }
}
const userStore = new TestUserStore();

describe('authentication', () => {
  it('should not authenticate a user coming with a non-existent username', async () => {
    const a = new Authenticator({userStore});
    const user = await a.authenticate('user0', '1234');
    expect(user.isAuthenticated).toBe(false);
  });
  it('should authenticate a user coming with a correct password', async () => {
    const a = new Authenticator({userStore});
    const user = await a.authenticate('user1', '1234');
    expect(user.isAuthenticated).toBe(true);
  });
  it('should not authenticate a user coming with an incorrect password', async () => {
    const a = new Authenticator({userStore});
    const user = await a.authenticate('user1', '5678');
    expect(user.isAuthenticated).toBe(false);
  });
});