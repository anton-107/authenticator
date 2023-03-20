"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ScryptHashingFunction = exports.handleError = void 0;
const crypto_1 = require("crypto");
function handleError(message, error, reject) {
  if (error === null) {
    return;
  }
  console.error(`Error: ${message}: ${error}`);
  reject(`Error: ${message}: ${error}`);
}
exports.handleError = handleError;
class ScryptHashingFunction {
  generateHash(password) {
    return new Promise((resolve, reject) => {
      const salt = (0, crypto_1.randomBytes)(128).toString("hex");
      (0, crypto_1.scrypt)(password, salt, 64, (err, key) => {
        handleError("Error generating scrypt hash", err, reject);
        resolve(`${salt}.${key.toString("hex")}`);
      });
    });
  }
  verifyPasswordHash(password, passwordHash) {
    return new Promise((resolve, reject) => {
      const parts = passwordHash.split(".");
      if (parts.length !== 2) {
        return reject(`Error getting salt from hash: ${passwordHash}`);
      }
      const salt = parts[0];
      const hash = parts[1];
      (0, crypto_1.scrypt)(password, salt, 64, (err, key) => {
        handleError("Error generating scrypt hash", err, reject);
        if (hash !== key.toString("hex")) {
          return resolve(false);
        }
        resolve(true);
      });
    });
  }
}
exports.ScryptHashingFunction = ScryptHashingFunction;
