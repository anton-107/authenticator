"use strict";
var __createBinding =
  (this && this.__createBinding) ||
  (Object.create
    ? function (o, m, k, k2) {
        if (k2 === undefined) k2 = k;
        var desc = Object.getOwnPropertyDescriptor(m, k);
        if (
          !desc ||
          ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)
        ) {
          desc = {
            enumerable: true,
            get: function () {
              return m[k];
            },
          };
        }
        Object.defineProperty(o, k2, desc);
      }
    : function (o, m, k, k2) {
        if (k2 === undefined) k2 = k;
        o[k2] = m[k];
      });
var __setModuleDefault =
  (this && this.__setModuleDefault) ||
  (Object.create
    ? function (o, v) {
        Object.defineProperty(o, "default", { enumerable: true, value: v });
      }
    : function (o, v) {
        o["default"] = v;
      });
var __importStar =
  (this && this.__importStar) ||
  function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null)
      for (var k in mod)
        if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k))
          __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
  };
Object.defineProperty(exports, "__esModule", { value: true });
exports.JWTSerializer =
  exports.SimpleStringProvider =
  exports.StandardJwtImplementation =
    void 0;
const jwt = __importStar(require("jsonwebtoken"));
class StandardJwtImplementation {
  sign(payload, secretOrPrivateKey, options, callback) {
    return jwt.sign(payload, secretOrPrivateKey, options, callback);
  }
  verify(token, secretOrPublicKey, callback) {
    return jwt.verify(token, secretOrPublicKey, callback);
  }
}
exports.StandardJwtImplementation = StandardJwtImplementation;
class SimpleStringProvider {
  constructor(secret) {
    this.secret = secret;
  }
  async getSecretKey() {
    return this.secret;
  }
}
exports.SimpleStringProvider = SimpleStringProvider;
class JWTSerializer {
  constructor(properties) {
    this.properties = properties;
  }
  async generateAccessToken(username) {
    let secretKey = "";
    try {
      secretKey = await this.properties.secretKeyProvider.getSecretKey();
    } catch (err) {
      throw Error("Secret key provider error");
    }
    return new Promise((resolve, reject) => {
      this.properties.jwt.sign(
        { username },
        secretKey,
        { expiresIn: 15 * 60 },
        (err, token) => {
          if (err) {
            return reject("jwt signing failed");
          }
          if (token === undefined) {
            return reject("jwt signing failed");
          }
          return resolve(token);
        }
      );
    });
  }
  async decodeAccessToken(accessToken) {
    let secretKey = "";
    try {
      secretKey = await this.properties.secretKeyProvider.getSecretKey();
    } catch (err) {
      throw "Secret key provider error";
    }
    return new Promise((resolve, reject) => {
      this.properties.jwt.verify(accessToken, secretKey, (err, payload) => {
        if (err) {
          return reject("Invalid token payload");
        }
        if (!payload) {
          return reject("Empty payload");
        }
        if (!payload["username"]) {
          return reject("No username in payload");
        }
        resolve(payload["username"]);
      });
    });
  }
}
exports.JWTSerializer = JWTSerializer;
