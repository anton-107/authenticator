import { handleError, ScryptHashingFunction } from "../src/scrypt-hashing";

describe("ScryptHashingFunction:verifyPasswordHash", () => {
  it("should reject passwords with incorrect format", async () => {
    const h = new ScryptHashingFunction();
    expect(() =>
      h.verifyPasswordHash("test", "this.passwordhash.has.more.parts")
    ).rejects.toEqual(
      "Error getting salt from hash: this.passwordhash.has.more.parts"
    );
  });
});

describe("ScryptHashingFunction:handleError", () => {
  it("should call reject if error is passed", async () => {
    const reject = jest.fn();
    handleError("test error", new Error(), reject);
    expect(reject.mock.calls.length).toBe(1);
  });
});
