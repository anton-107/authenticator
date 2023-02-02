"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.RuntimeError = void 0;
class RuntimeError {
    constructor(message, payload) {
        this.message = message;
        this.payload = payload;
    }
    toString() {
        return this.message;
    }
}
exports.RuntimeError = RuntimeError;
