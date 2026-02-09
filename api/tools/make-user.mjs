import crypto from "node:crypto";

const username = process.argv[2];
const password = process.argv[3];
if (!username || !password) {
  console.log("Usage: node tools/make-user.mjs <username> <password>");
  process.exit(1);
}

// Cloudflare Workers WebCrypto PBKDF2 currently supports up to 100000 iterations.
const iters = 100000;
const salt = crypto.randomBytes(16);
const hash = crypto.pbkdf2Sync(password, salt, iters, 32, "sha256");

const b64url = (buf) =>
  buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");

const user = {
  id: crypto.randomUUID(),
  username: username.toLowerCase(),
  pw_salt: b64url(salt),
  pw_hash: b64url(hash),
  pw_iters: iters,
};

const sqlQuote = (v) => `'${String(v).replace(/'/g, "''")}'`;

const upsertSql =
  "INSERT INTO users (id, username, pw_hash, pw_salt, pw_iters, created_at) " +
  `VALUES (${sqlQuote(user.id)}, ${sqlQuote(user.username)}, ${sqlQuote(user.pw_hash)}, ${sqlQuote(user.pw_salt)}, ${user.pw_iters}, datetime('now')) ` +
  "ON CONFLICT(username) DO UPDATE SET " +
  "pw_hash=excluded.pw_hash, " +
  "pw_salt=excluded.pw_salt, " +
  "pw_iters=excluded.pw_iters;";

console.log(JSON.stringify(user, null, 2));
console.log("\nSQL:\n");
console.log(upsertSql);
