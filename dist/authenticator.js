"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Authenticator = void 0;
const runtime_error_1 = require("./runtime-error");
class Authenticator {
    constructor(props) {
        this.props = props;
    }
    async addUser(username, password) {
        this.props.userStore.addUser({
            username,
            passwordHash: await this.props.passwordHashingFunction.generateHash(password),
        });
    }
    async signIn(username, password) {
        const user = await this.props.userStore.getUserByName(username);
        if (!user) {
            return {
                isAuthenticated: false,
                authenticationFailedReason: `User with name '${username}' is not found`,
            };
        }
        try {
            const isAuthenticated = await this.props.passwordHashingFunction.verifyPasswordHash(password, user.passwordHash);
            if (!isAuthenticated) {
                return {
                    isAuthenticated: false,
                    authenticationFailedReason: `User '${username}' is found, but the given password of length(${password.length}) is incorrect`,
                };
            }
            const accessToken = await this.props.authTokensSerializer.generateAccessToken(username);
            return {
                isAuthenticated: true,
                accessToken: `jwt ${accessToken}`,
            };
        }
        catch (err) {
            console.error("Error verifying hash or generating access token", err);
            return {
                isAuthenticated: false,
            };
        }
    }
    async authenticate(accessToken) {
        try {
            const username = await this.readToken(accessToken);
            return {
                isAuthenticated: true,
                username,
            };
        }
        catch (err) {
            console.error("Authentication error", err);
            return {
                isAuthenticated: false,
                errorMessage: String(err),
            };
        }
    }
    async readToken(accessToken) {
        const [tokenType, token] = accessToken.split(" ");
        if (tokenType !== "jwt") {
            throw new runtime_error_1.RuntimeError("Token type is not supported", { tokenType });
        }
        if (!token || token.length === 0) {
            throw new runtime_error_1.RuntimeError("Empty token payload", { token });
        }
        return await this.props.authTokensSerializer.decodeAccessToken(token);
    }
}
exports.Authenticator = Authenticator;
