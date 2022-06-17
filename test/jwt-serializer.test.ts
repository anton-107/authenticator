import { mock, instance, when, anything } from "ts-mockito";
import { JWT, JWTSerializer } from "./../src/jwt-serializer";

describe("JWTSerializer", () => {
  it("rejects token signing on jwt error", () => {
    const jwt = mock<JWT>();
    when(jwt.sign(anything(), anything(), anything(), anything())).thenCall(
      (payload, secret, options, callback) => {
        callback("test error");
      }
    );
    const serializer = new JWTSerializer({
      jwt: instance(jwt),
      secretKey: "secret-key",
    });
    expect(() => serializer.generateAccessToken("user1")).rejects.toBe(
      "jwt signing failed"
    );
  });
  it("rejects token signing on undefined token returned", () => {
    const jwt = mock<JWT>();
    when(jwt.sign(anything(), anything(), anything(), anything())).thenCall(
      (payload, secret, options, callback) => {
        callback(null, undefined);
      }
    );
    const serializer = new JWTSerializer({
      jwt: instance(jwt),
      secretKey: "secret-key",
    });
    expect(() => serializer.generateAccessToken("user1")).rejects.toBe(
      "jwt signing failed"
    );
  });
  it("rejects token decoding on jwt error", () => {
    const jwt = mock<JWT>();
    when(jwt.verify(anything(), anything(), anything())).thenCall(
      (token, secret, callback) => {
        callback("test error", undefined);
      }
    );
    const serializer = new JWTSerializer({
      jwt: instance(jwt),
      secretKey: "secret-key",
    });
    expect(() => serializer.decodeAccessToken("user1-token")).rejects.toBe(
      "Invalid token payload"
    );
  });
  it("rejects token decoding on undefined payload returned", () => {
    const jwt = mock<JWT>();
    when(jwt.verify(anything(), anything(), anything())).thenCall(
      (token, secret, callback) => {
        callback(null, undefined);
      }
    );
    const serializer = new JWTSerializer({
      jwt: instance(jwt),
      secretKey: "secret-key",
    });
    expect(() => serializer.decodeAccessToken("user1-token")).rejects.toBe(
      "Empty payload"
    );
  });
  it("rejects token decoding on no username in returned payload", () => {
    const jwt = mock<JWT>();
    when(jwt.verify(anything(), anything(), anything())).thenCall(
      (token, secret, callback) => {
        callback(null, { someField: "test" });
      }
    );
    const serializer = new JWTSerializer({
      jwt: instance(jwt),
      secretKey: "secret-key",
    });
    expect(() => serializer.decodeAccessToken("user1-token")).rejects.toBe(
      "No username in payload"
    );
  });
});
