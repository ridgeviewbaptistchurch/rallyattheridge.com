import crypto from "node:crypto";

const username = process.argv[2];
const password = process.argv[3];
if (!username || !password) {
  console.log("Usage: node tools/make-user.mjs <username> <password>");
  process.exit(1);
}

const iters = 150000;
const salt = crypto.randomBytes(16);
const hash = crypto.pbkdf2Sync(password, salt, iters, 32, "sha256");

const b64url = (buf) =>
  buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");

console.log(JSON.stringify({
  id: crypto.randomUUID(),
  username: username.toLowerCase(),
  pw_salt: b64url(salt),
  pw_hash: b64url(hash),
  pw_iters: iters,
}, null, 2));
