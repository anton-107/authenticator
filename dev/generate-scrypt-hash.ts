import { ScryptHashingFunction } from "../src/scrypt-hashing";

async function main(logger) {
  const f = new ScryptHashingFunction();
  const p = process.env.PASSWORD || "";
  const hash = await f.generateHash(p);
  logger.log(`Scrypt hash for ${p} is: ${hash}`);
}

main(console);
