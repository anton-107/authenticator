import { PasswordHashingFunction } from "./authenticator";
export declare function handleError(message: string, error: Error | null, reject: (message: string) => void): void;
export declare class ScryptHashingFunction implements PasswordHashingFunction {
    generateHash(password: string): Promise<string>;
    verifyPasswordHash(password: string, passwordHash: string): Promise<boolean>;
}
