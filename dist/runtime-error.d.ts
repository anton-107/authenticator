declare type ErrorPayload = {
  [key: string]: string;
};
export declare class RuntimeError {
  private message;
  private payload;
  constructor(message: string, payload: ErrorPayload);
  toString(): string;
}
export {};
