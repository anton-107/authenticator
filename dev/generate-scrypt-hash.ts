import { ScryptHashingFunction } from "../src/scrypt-hashing";

async function main() {
  const f = new ScryptHashingFunction();
  const p = process.env.PASSWORD || "";
  const hash = await f.generateHash(p);
  console.log(`Scrypt hash for ${p} is: ${hash}`);
}

main();
