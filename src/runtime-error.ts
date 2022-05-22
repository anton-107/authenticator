type ErrorPayload = { [key: string]: string };

export class RuntimeError {
  constructor(private message: string, private payload: ErrorPayload) {}
  public toString() {
    return this.message;
  }
}
