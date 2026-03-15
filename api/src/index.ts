import { Toucan } from "toucan-js";

type Env = {
  DB: D1Database;
  PUBLIC_SITE_URL: string;
  AUTH_SECRET: string;
  SENTRY_DSN?: string;
  SENTRY_ENVIRONMENT?: string;
  SENDER_API_KEY?: string;
  SENDER_TEMPLATE_CONFIRMATION?: string;  // Sender.net template ID for registration confirmation
  SENDER_GROUP_ID?: string;              // Sender.net group ID to subscribe registrants to
  SHOW_DATE?: string;         // e.g. "September 12, 2026"
};

const SESSION_COOKIE = "carshow_sess";
const SESSION_TTL_SECONDS = 60 * 60 * 12; // 12 hours
const MAX_PBKDF2_ITERS = 100000;
const LOGIN_LIMIT = { max: 10, windowSeconds: 10 * 60 };
const PUBLIC_REGISTER_LIMIT = { max: 20, windowSeconds: 60 * 60 };
const PROD_ALLOWED_ORIGIN = "https://rallyattheridge.org";
const REG_INSERT_MAX_RETRIES = 5;
const FIELD_MAX = {
  name: 120,
  email: 254,
  phone: 40,
  address: 200,
  carYear: 16,
  carMake: 80,
  carModel: 80,
  carColor: 60,
  homeChurchName: 120,
} as const;
let rateLimitTableReady = false;

function parseCookies(req: Request): Record<string, string> {
  const h = req.headers.get("Cookie") || "";
  const out: Record<string, string> = {};
  for (const part of h.split(";")) {
    const [k, ...v] = part.trim().split("=");
    if (!k) continue;
    out[k] = decodeURIComponent(v.join("=") || "");
  }
  return out;
}

function b64url(bytes: Uint8Array): string {
  const bin = String.fromCharCode(...bytes);
  const b64 = btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  return b64;
}

function unb64url(s: string): Uint8Array {
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4);
  const bin = atob(b64);
  return new Uint8Array([...bin].map(c => c.charCodeAt(0)));
}

async function hmacSign(secret: string, data: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(data));
  return b64url(new Uint8Array(sig));
}

async function makeSessionCookie(env: Env, userId: string): Promise<string> {
  const exp = Math.floor(Date.now() / 1000) + SESSION_TTL_SECONDS;
  const payload = `${userId}.${exp}`;
  const sig = await hmacSign(env.AUTH_SECRET, payload);
  // value = userId.exp.sig
  return `${userId}.${exp}.${sig}`;
}

async function verifySession(env: Env, cookieVal: string | undefined): Promise<{ userId: string } | null> {
  if (!cookieVal) return null;
  const parts = cookieVal.split(".");
  if (parts.length !== 3) return null;
  const [userId, expStr, sig] = parts;
  const exp = Number(expStr);
  if (!userId || !Number.isFinite(exp)) return null;
  if (exp < Math.floor(Date.now() / 1000)) return null;

  const payload = `${userId}.${exp}`;
  const expected = await hmacSign(env.AUTH_SECRET, payload);
  if (expected !== sig) return null;
  return { userId };
}

function isLocalDevOrigin(origin: string | null): boolean {
  if (!origin) return false;
  try {
    const { hostname } = new URL(origin);
    return hostname === "localhost" || hostname === "127.0.0.1" || hostname.endsWith(".localhost");
  } catch {
    return false;
  }
}

function isAllowedCorsOrigin(origin: string | null): boolean {
  if (!origin) return false;
  if (origin === PROD_ALLOWED_ORIGIN) return true;
  return isLocalDevOrigin(origin);
}

function setCookieHeader(req: Request, value: string): string {
  // Local dev from localhost -> api.rallyattheridge.org is cross-site, so SameSite=None is required.
  // Production on the same site can keep SameSite=Lax.
  const sameSite = isLocalDevOrigin(req.headers.get("Origin")) ? "None" : "Lax";
  return `${SESSION_COOKIE}=${encodeURIComponent(value)}; Path=/; HttpOnly; Secure; SameSite=${sameSite}; Max-Age=${SESSION_TTL_SECONDS}`;
}

function clearCookieHeader(req: Request): string {
  const sameSite = isLocalDevOrigin(req.headers.get("Origin")) ? "None" : "Lax";
  return `${SESSION_COOKIE}=; Path=/; HttpOnly; Secure; SameSite=${sameSite}; Max-Age=0`;
}

// Password hashing (PBKDF2)
async function pbkdf2Hash(password: string, saltBytes: Uint8Array, iterations: number): Promise<Uint8Array> {
  if (!Number.isFinite(iterations) || iterations <= 0) {
    throw new Error("Invalid PBKDF2 iteration count");
  }
  if (iterations > MAX_PBKDF2_ITERS) {
    throw new Error(`Unsupported PBKDF2 iteration count: ${iterations}`);
  }

  const baseKey = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt: saltBytes, iterations },
    baseKey,
    256
  );
  return new Uint8Array(bits);
}

function corsHeadersFor(req: Request): Record<string, string> {
  const origin = req.headers.get("Origin");
  const headers: Record<string, string> = {
    "access-control-allow-methods": "GET,POST,OPTIONS",
    "access-control-allow-headers": "content-type",
    "vary": "Origin",
  };

  if (origin && isAllowedCorsOrigin(origin)) {
    headers["access-control-allow-origin"] = origin;
    headers["access-control-allow-credentials"] = "true";
  }

  return headers;
}

const json = (data: unknown, init: ResponseInit = {}) =>
  new Response(JSON.stringify(data), {
    ...init,
    headers: {
      "content-type": "application/json; charset=utf-8",
      ...(init.headers || {}),
    },
  });

const html = (body: string, init: ResponseInit = {}) =>
  new Response(body, {
    ...init,
    headers: {
      "content-type": "text/html; charset=utf-8",
      ...(init.headers || {}),
    },
  });

const text = (body: string, init: ResponseInit = {}) =>
  new Response(body, {
    ...init,
    headers: {
      "content-type": "text/plain; charset=utf-8",
      ...(init.headers || {}),
    },
  });

const isoNow = () => new Date().toISOString();

const toInt = (v: unknown) => {
  const n = Number(v);
  return Number.isFinite(n) ? Math.trunc(n) : NaN;
};

const escapeHtml = (s: string) =>
  s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");

function requireClass(c: unknown): "car_truck" | "motorcycle" | "other" | null {
  if (c === "car_truck" || c === "motorcycle" || c === "other") return c;
  return null;
}

function normalize(s: unknown): string {
  return String(s ?? "").trim();
}

function tooLong(s: string, max: number): boolean {
  return s.length > max;
}

function requireYesNo(v: unknown): "yes" | "no" | null {
  if (v === "yes" || v === "no") return v;
  return null;
}

function requireTshirtSize(v: unknown): "small" | "medium" | "large" | "xl" | "2xl" | "3xl" | null {
  if (v === "small" || v === "medium" || v === "large" || v === "xl" || v === "2xl" || v === "3xl") return v;
  return null;
}

async function nextRegNumber(db: D1Database): Promise<number> {
  const r = await db.prepare("SELECT COALESCE(MAX(reg_number), 0) AS m FROM registrations").first<{ m: number }>();
  return (r?.m ?? 0) + 1;
}

function isRegNumberConflict(err: unknown): boolean {
  const msg = String((err as any)?.message || err || "");
  return msg.includes("UNIQUE constraint failed") && msg.includes("registrations.reg_number");
}

type RegistrationInput = {
  name: string;
  email: string;
  phone: string;
  address: string;
  car_year: string;
  car_make: string;
  car_model: string;
  car_color: string;
  cls: "car_truck" | "motorcycle" | "other";
  attended_before: "yes" | "no";
  tshirt_size: "small" | "medium" | "large" | "xl" | "2xl" | "3xl";
  has_home_church: "yes" | "no";
  home_church_name: string;
};

async function createRegistrationWithRetry(
  db: D1Database,
  input: RegistrationInput,
  autoCheckIn: boolean
): Promise<{ id: string; reg_number: number; created_at: string }> {
  for (let attempt = 1; attempt <= REG_INSERT_MAX_RETRIES; attempt++) {
    const reg_number = await nextRegNumber(db);
    const id = crypto.randomUUID();
    const created_at = isoNow();

    try {
      if (autoCheckIn) {
        await db.prepare(
          `INSERT INTO registrations
           (id, reg_number, created_at, checked_in_at, name, email, phone, address, car_year, car_make, car_model, car_color, class, attended_before, tshirt_size, has_home_church, home_church_name)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
        )
          .bind(
            id,
            reg_number,
            created_at,
            created_at,
            input.name,
            input.email || null,
            input.phone || null,
            input.address,
            input.car_year,
            input.car_make,
            input.car_model,
            input.car_color,
            input.cls,
            input.attended_before,
            input.tshirt_size,
            input.has_home_church,
            input.home_church_name || null
          )
          .run();
      } else {
        await db.prepare(
          `INSERT INTO registrations
           (id, reg_number, created_at, name, email, phone, address, car_year, car_make, car_model, car_color, class, attended_before, tshirt_size, has_home_church, home_church_name)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
        )
          .bind(
            id,
            reg_number,
            created_at,
            input.name,
            input.email || null,
            input.phone || null,
            input.address,
            input.car_year,
            input.car_make,
            input.car_model,
            input.car_color,
            input.cls,
            input.attended_before,
            input.tshirt_size,
            input.has_home_church,
            input.home_church_name || null
          )
          .run();
      }

      return { id, reg_number, created_at };
    } catch (err) {
      if (!isRegNumberConflict(err) || attempt === REG_INSERT_MAX_RETRIES) throw err;
    }
  }

  throw new Error("Could not allocate registration number");
}

function match(pathname: string, pattern: RegExp): RegExpExecArray | null {
  return pattern.exec(pathname);
}

function clientIpFor(req: Request): string {
  const cfIp = req.headers.get("cf-connecting-ip");
  if (cfIp) return cfIp.trim();

  const forwarded = req.headers.get("x-forwarded-for");
  if (forwarded) return forwarded.split(",")[0].trim();

  return "0.0.0.0";
}

async function consumeRateLimit(
  db: D1Database,
  key: string,
  maxHits: number,
  windowSeconds: number
): Promise<{ allowed: boolean; retryAfterSeconds: number }> {
  if (!rateLimitTableReady) {
    await db.prepare(
      `CREATE TABLE IF NOT EXISTS rate_limits (
         k TEXT NOT NULL,
         window_start INTEGER NOT NULL,
         hit_count INTEGER NOT NULL,
         expires_at INTEGER NOT NULL,
         PRIMARY KEY (k, window_start)
       )`
    ).run();
    await db.prepare(
      `CREATE INDEX IF NOT EXISTS idx_rate_limits_expires ON rate_limits(expires_at)`
    ).run();
    rateLimitTableReady = true;
  }

  const now = Math.floor(Date.now() / 1000);
  const windowStart = now - (now % windowSeconds);
  const expiresAt = windowStart + windowSeconds + 60;

  await db
    .prepare(
      `INSERT INTO rate_limits (k, window_start, hit_count, expires_at)
       VALUES (?, ?, 1, ?)
       ON CONFLICT(k, window_start) DO UPDATE SET
         hit_count = hit_count + 1,
         expires_at = excluded.expires_at`
    )
    .bind(key, windowStart, expiresAt)
    .run();

  const row = await db
    .prepare(
      `SELECT hit_count
       FROM rate_limits
       WHERE k = ? AND window_start = ?`
    )
    .bind(key, windowStart)
    .first<{ hit_count: number }>();

  const hitCount = Number(row?.hit_count ?? 0);
  if (hitCount <= maxHits) {
    return { allowed: true, retryAfterSeconds: 0 };
  }

  const retryAfterSeconds = Math.max(1, windowStart + windowSeconds - now);
  return { allowed: false, retryAfterSeconds };
}

async function gcRateLimits(db: D1Database): Promise<void> {
  const now = Math.floor(Date.now() / 1000);
  await db.prepare(`DELETE FROM rate_limits WHERE expires_at < ?`).bind(now).run();
}

// ─── Email helpers ────────────────────────────────────────────────────────────

async function sendTemplateEmail(
  env: Env,
  templateId: string,
  recipientEmail: string,
  variables: Record<string, string>,
  sentry?: Toucan | null
): Promise<boolean> {
  if (!env.SENDER_API_KEY) return false;
  try {
    const resp = await fetch(`https://api.sender.net/v2/message/${encodeURIComponent(templateId)}/send`, {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${env.SENDER_API_KEY}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ recipient_email: recipientEmail, variables }),
    });
    if (!resp.ok) {
      const body = await resp.text().catch(() => "(unreadable)");
      console.error(`Sender.net template email failed: HTTP ${resp.status} — ${body}`);
      sentry?.captureException(new Error(`Sender.net error: HTTP ${resp.status} — ${body}`));
    }
    return resp.ok;
  } catch (err) {
    console.error("Sender.net template email exception:", err);
    sentry?.captureException(err);
    return false;
  }
}

async function addSenderSubscriber(
  env: Env,
  email: string,
  firstname: string,
  lastname: string,
  sentry?: Toucan | null
): Promise<void> {
  if (!env.SENDER_API_KEY || !env.SENDER_GROUP_ID) return;
  try {
    const resp = await fetch("https://api.sender.net/v2/subscribers", {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${env.SENDER_API_KEY}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ email, firstname, lastname, groups: [env.SENDER_GROUP_ID] }),
    });
    if (!resp.ok) {
      const body = await resp.text().catch(() => "(unreadable)");
      sentry?.captureException(new Error(`Sender.net subscriber error: HTTP ${resp.status} — ${body}`));
    }
  } catch (err) {
    sentry?.captureException(err);
  }
}

// ─── End email helpers ─────────────────────────────────────────────────────────

export default {
  async fetch(req: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const corsHeaders = corsHeadersFor(req);
    const sentry = env.SENTRY_DSN
      ? new Toucan({
          dsn: env.SENTRY_DSN,
          context: ctx,
          request: req,
          environment: env.SENTRY_ENVIRONMENT || "production",
        })
      : null;

    try {
      const url = new URL(req.url);
      const { pathname } = url;
      const bad = (message: string, status = 400) =>
        json({ ok: false, error: message }, { status, headers: corsHeaders });
      const origin = req.headers.get("Origin");

      if (pathname.startsWith("/api/") && origin && !isAllowedCorsOrigin(origin)) {
        return json({ ok: false, error: "Origin not allowed" }, { status: 403, headers: { vary: "Origin" } });
      }

      if (rateLimitTableReady && pathname.startsWith("/api/") && Math.random() < 0.01) {
        await gcRateLimits(env.DB);
      }

      // CORS preflight
      if (req.method === "OPTIONS" && pathname.startsWith("/api/")) {
        if (origin && !isAllowedCorsOrigin(origin)) {
          return json({ ok: false, error: "Origin not allowed" }, { status: 403, headers: { vary: "Origin" } });
        }
        return new Response(null, { status: 204, headers: corsHeaders });
      }

      // Friendly root (optional)
      if (req.method === "GET" && pathname === "/") {
        return text("Car Show API is running. Try /api/health");
      }

      // Health
      if (req.method === "GET" && pathname === "/api/health") {
        return json({ ok: true }, { headers: corsHeaders });
      }

      //Login
      if (req.method === "POST" && pathname === "/api/admin/login") {
        const ip = clientIpFor(req);
        const rl = await consumeRateLimit(env.DB, `login:${ip}`, LOGIN_LIMIT.max, LOGIN_LIMIT.windowSeconds);
        if (!rl.allowed) {
          return json(
            { ok: false, error: "Too many login attempts. Please try again later." },
            {
              status: 429,
              headers: {
                ...corsHeaders,
                "retry-after": String(rl.retryAfterSeconds),
              },
            }
          );
        }

        const body = (await req.json().catch(() => null)) as any;
        if (!body) return bad("Invalid JSON");

        const username = normalize(body.username).toLowerCase();
        const password = String(body.password ?? "");

        if (!username || !password) return bad("Username and password required");
        if (tooLong(username, 80)) return bad("Username is too long");
        if (tooLong(password, 256)) return bad("Password is too long");

        const user = await env.DB.prepare(
          `SELECT id, pw_hash, pw_salt, pw_iters FROM users WHERE username = ?`
        ).bind(username).first<any>();

        if (!user) return bad("Invalid login", 401);

        const salt = unb64url(user.pw_salt);
        const iters = Number(user.pw_iters);

        if (iters > MAX_PBKDF2_ITERS) {
          return json(
            { ok: false, error: `Admin password hash requires ${iters} PBKDF2 iterations, but this runtime supports up to ${MAX_PBKDF2_ITERS}. Recreate the admin user with a lower iteration count.` },
            { status: 500, headers: corsHeaders }
          );
        }

        const computed = await pbkdf2Hash(password, salt, iters);
        const computedB64 = b64url(computed);

        if (computedB64 !== user.pw_hash) return bad("Invalid login", 401);

        const sess = await makeSessionCookie(env, user.id);
        return json(
          { ok: true },
          {
            headers: {
              ...corsHeaders,
              "set-cookie": setCookieHeader(req, sess),
            },
          }
        );
      }

      // POST /api/admin/logout
      if (req.method === "POST" && pathname === "/api/admin/logout") {
        return json(
          { ok: true },
          {
            headers: {
              ...corsHeaders,
              "set-cookie": clearCookieHeader(req),
            },
          }
        );
      }

      const isProtectedApi =
        (pathname.startsWith("/api/admin/") &&
          pathname !== "/api/admin/login") ||
        pathname === "/api/votes" ||
        pathname === "/api/tally" ||
        pathname === "/api/prizes/draw" ||
        pathname === "/api/prizes/winners";

      let session: { userId: string } | null = null;
      if (isProtectedApi) {
        const cookies = parseCookies(req);
        session = await verifySession(env, cookies[SESSION_COOKIE]);
        if (!session) return json({ ok: false, error: "Unauthorized" }, { status: 401, headers: corsHeaders });
      }

      // GET /api/admin/session
      if (req.method === "GET" && pathname === "/api/admin/session") {
        return json({ ok: true, userId: session?.userId ?? null }, { headers: corsHeaders });
      }

      // POST /api/admin/register (register + auto check-in)
      if (req.method === "POST" && pathname === "/api/admin/register") {
        const body = (await req.json().catch(() => null)) as any;
        if (!body) return bad("Invalid JSON");

        const name = normalize(body.name);
        const email = normalize(body.email);
        const phone = normalize(body.phone);
        const address = normalize(body.address);

        const car_year = normalize(body.car_year);
        const car_make = normalize(body.car_make);
        const car_model = normalize(body.car_model);
        const car_color = normalize(body.car_color);

        const cls = requireClass(body.class);
        const attended_before = requireYesNo(body.attended_before);
        const tshirt_size = requireTshirtSize(body.tshirt_size);
        const has_home_church = requireYesNo(body.has_home_church);
        const home_church_name = normalize(body.home_church_name);

        if (!name) return bad("Name is required");
        if (!address) return bad("Address is required");
        if (!car_year || !car_make || !car_model || !car_color) return bad("Car year/make/model/color are required");
        if (!cls) return bad("Class is required");
        if (!attended_before) return bad("Please select if you have attended before");
        if (!tshirt_size) return bad("Please select a t-shirt size");
        if (!has_home_church) return bad("Please select if you have a home church");
        if (has_home_church === "yes" && !home_church_name) return bad("Home church name is required when selected");
        if (tooLong(name, FIELD_MAX.name)) return bad("Name is too long");
        if (email && tooLong(email, FIELD_MAX.email)) return bad("Email is too long");
        if (phone && tooLong(phone, FIELD_MAX.phone)) return bad("Phone is too long");
        if (tooLong(address, FIELD_MAX.address)) return bad("Address is too long");
        if (tooLong(car_year, FIELD_MAX.carYear)) return bad("Car year is too long");
        if (tooLong(car_make, FIELD_MAX.carMake)) return bad("Car make is too long");
        if (tooLong(car_model, FIELD_MAX.carModel)) return bad("Car model is too long");
        if (tooLong(car_color, FIELD_MAX.carColor)) return bad("Car color is too long");
        if (home_church_name && tooLong(home_church_name, FIELD_MAX.homeChurchName)) return bad("Home church name is too long");

        const { reg_number, id, created_at } = await createRegistrationWithRetry(
          env.DB,
          {
            name,
            email,
            phone,
            address,
            car_year,
            car_make,
            car_model,
            car_color,
            cls,
            attended_before,
            tshirt_size,
            has_home_church,
            home_church_name,
          },
          true
        );

        return json(
          {
            ok: true,
            reg_number,
            id,
            checked_in_at: created_at,
            print_url: `${env.PUBLIC_SITE_URL.replace(/\/+$/, "")}/admin/print.html?car=${reg_number}`,
          },
          { headers: corsHeaders }
        );
      }



      // POST /api/register
      if (req.method === "POST" && pathname === "/api/register") {
        const ip = clientIpFor(req);
        const rl = await consumeRateLimit(
          env.DB,
          `public-register:${ip}`,
          PUBLIC_REGISTER_LIMIT.max,
          PUBLIC_REGISTER_LIMIT.windowSeconds
        );
        if (!rl.allowed) {
          return json(
            { ok: false, error: "Too many registration attempts. Please try again later." },
            {
              status: 429,
              headers: {
                ...corsHeaders,
                "retry-after": String(rl.retryAfterSeconds),
              },
            }
          );
        }

        const body = (await req.json().catch(() => null)) as any;
        if (!body) return bad("Invalid JSON");

        const name = normalize(body.name);
        const email = normalize(body.email);
        const phone = normalize(body.phone);
        const address = normalize(body.address);

        const car_year = normalize(body.car_year);
        const car_make = normalize(body.car_make);
        const car_model = normalize(body.car_model);
        const car_color = normalize(body.car_color);

        const cls = requireClass(body.class);
        const attended_before = requireYesNo(body.attended_before);
        const tshirt_size = requireTshirtSize(body.tshirt_size);
        const has_home_church = requireYesNo(body.has_home_church);
        const home_church_name = normalize(body.home_church_name);

        if (!name) return bad("Name is required");
        if (!address) return bad("Address is required");
        if (!car_year || !car_make || !car_model || !car_color) return bad("Car year/make/model/color are required");
        if (!cls) return bad("Class is required");
        if (!attended_before) return bad("Please select if you have attended before");
        if (!tshirt_size) return bad("Please select a t-shirt size");
        if (!has_home_church) return bad("Please select if you have a home church");
        if (has_home_church === "yes" && !home_church_name) return bad("Home church name is required when selected");
        if (tooLong(name, FIELD_MAX.name)) return bad("Name is too long");
        if (email && tooLong(email, FIELD_MAX.email)) return bad("Email is too long");
        if (phone && tooLong(phone, FIELD_MAX.phone)) return bad("Phone is too long");
        if (tooLong(address, FIELD_MAX.address)) return bad("Address is too long");
        if (tooLong(car_year, FIELD_MAX.carYear)) return bad("Car year is too long");
        if (tooLong(car_make, FIELD_MAX.carMake)) return bad("Car make is too long");
        if (tooLong(car_model, FIELD_MAX.carModel)) return bad("Car model is too long");
        if (tooLong(car_color, FIELD_MAX.carColor)) return bad("Car color is too long");
        if (home_church_name && tooLong(home_church_name, FIELD_MAX.homeChurchName)) return bad("Home church name is too long");

        const { reg_number, id } = await createRegistrationWithRetry(
          env.DB,
          {
            name,
            email,
            phone,
            address,
            car_year,
            car_make,
            car_model,
            car_color,
            cls,
            attended_before,
            tshirt_size,
            has_home_church,
            home_church_name,
          },
          false
        );

        if (email && env.SENDER_API_KEY && env.SENDER_TEMPLATE_CONFIRMATION) {
          const [firstname, ...rest] = name.split(" ");
          const lastname = rest.join(" ");
          ctx.waitUntil(Promise.all([
            sendTemplateEmail(
              env,
              env.SENDER_TEMPLATE_CONFIRMATION,
              email,
              { firstname, lastname, id_number: String(reg_number) },
              sentry
            ),
            addSenderSubscriber(env, email, firstname, lastname, sentry),
          ]));
        }

        return json(
          {
            ok: true,
            reg_number,
            id,
            print_url: `${env.PUBLIC_SITE_URL.replace(/\/+$/, "")}/admin/print.html?car=${reg_number}`,
          },
          { headers: corsHeaders }
        );
      }

      // GET /api/admin/search?q=...
      if (req.method === "GET" && pathname === "/api/admin/search") {
        const q = (url.searchParams.get("q") ?? "").trim();
        if (!q) return json({ ok: true, results: [] }, { headers: corsHeaders });

        const qLike = `%${q}%`;
        const maybeNum = toInt(q);

        const stmt = Number.isFinite(maybeNum)
          ? env.DB.prepare(
              `SELECT reg_number, name, car_year, car_make, car_model, car_color, class, checked_in_at
               FROM registrations
               WHERE reg_number = ? OR name LIKE ? OR email LIKE ? OR phone LIKE ?
               ORDER BY CASE WHEN reg_number = ? THEN 0 ELSE 1 END, reg_number DESC
               LIMIT 50`
            ).bind(maybeNum, qLike, qLike, qLike, maybeNum)
          : env.DB.prepare(
              `SELECT reg_number, name, car_year, car_make, car_model, car_color, class, checked_in_at
               FROM registrations
               WHERE name LIKE ? OR email LIKE ? OR phone LIKE ? OR car_make LIKE ? OR car_model LIKE ?
               ORDER BY reg_number DESC
               LIMIT 50`
            ).bind(qLike, qLike, qLike, qLike, qLike);

        const results = (await stmt.all()).results;
        return json({ ok: true, results }, { headers: corsHeaders });
      }

      // GET /api/admin/stats
      if (req.method === "GET" && pathname === "/api/admin/stats") {
        const row = await env.DB.prepare(
          `SELECT
             COUNT(*) AS total,
             SUM(CASE WHEN checked_in_at IS NOT NULL THEN 1 ELSE 0 END) AS checked_in,
             SUM(CASE WHEN checked_in_at IS NULL THEN 1 ELSE 0 END) AS not_checked_in
           FROM registrations
           WHERE id NOT LIKE 'test-%'`
        ).first<{ total: number; checked_in: number | null; not_checked_in: number | null }>();

        return json(
          {
            ok: true,
            stats: {
              total: Number(row?.total ?? 0),
              checked_in: Number(row?.checked_in ?? 0),
              not_checked_in: Number(row?.not_checked_in ?? 0),
            },
          },
          { headers: corsHeaders }
        );
      }

      // GET /api/admin/registration/:reg
      {
        const m = match(pathname, /^\/api\/admin\/registration\/(\d+)$/);
        if (req.method === "GET" && m) {
          const reg = toInt(m[1]);
          const row = await env.DB.prepare(
            `SELECT
               r.*,
               (SELECT COUNT(*) FROM votes v WHERE v.reg_number = r.reg_number) AS vote_count,
               (SELECT COUNT(*) FROM prize_winners pw WHERE pw.reg_number = r.reg_number) AS prize_win_count,
               (SELECT pw.prize_name
                FROM prize_winners pw
                WHERE pw.reg_number = r.reg_number
                ORDER BY pw.created_at DESC
                LIMIT 1) AS latest_prize_name,
               (SELECT pw.created_at
                FROM prize_winners pw
                WHERE pw.reg_number = r.reg_number
                ORDER BY pw.created_at DESC
                LIMIT 1) AS latest_prize_at
             FROM registrations r
             WHERE r.reg_number = ?`
          ).bind(reg).first();
          if (!row) return bad("Not found", 404);
          return json({ ok: true, registration: row }, { headers: corsHeaders });
        }
      }

      // POST /api/admin/registration/:reg/checkin
      {
        const m = match(pathname, /^\/api\/admin\/registration\/(\d+)\/checkin$/);
        if (req.method === "POST" && m) {
          const reg = toInt(m[1]);
          const now = isoNow();
          const r = await env.DB.prepare(
            `UPDATE registrations
             SET checked_in_at = COALESCE(checked_in_at, ?)
             WHERE reg_number = ?`
          )
            .bind(now, reg)
            .run();
          return json({ ok: true, updated: r.meta.changes }, { headers: corsHeaders });
        }
      }

      // POST /api/votes
      if (req.method === "POST" && pathname === "/api/votes") {
        const body = (await req.json().catch(() => null)) as any;
        if (!body) return bad("Invalid JSON");

        const inputRegs = Array.isArray(body.reg_numbers)
          ? body.reg_numbers
          : body.reg_number !== undefined
            ? [body.reg_number]
            : [];

        const regNumbers = inputRegs
          .map((v: unknown) => toInt(v))
          .filter((n: number) => Number.isFinite(n) && n > 0);

        if (!regNumbers.length) return bad("At least one valid reg number is required");

        const uniqueRegs = [...new Set(regNumbers)];
        const placeholders = uniqueRegs.map(() => "?").join(",");

        const regRows = (
          await env.DB.prepare(
            `SELECT reg_number, class
             FROM registrations
             WHERE reg_number IN (${placeholders})`
          )
            .bind(...uniqueRegs)
            .all<{ reg_number: number; class: "car_truck" | "motorcycle" | "other" }>()
        ).results;

        const regToClass = new Map<number, "car_truck" | "motorcycle" | "other">();
        for (const row of regRows) regToClass.set(Number(row.reg_number), row.class);

        const created_at = isoNow();
        const ballot_id = String(body.ballot_id ?? "").trim() || null;
        const invalid: number[] = [];
        const byClass = { car_truck: 0, motorcycle: 0, other: 0 };
        const inserts: D1PreparedStatement[] = [];

        for (const reg_number of regNumbers) {
          const cls = regToClass.get(reg_number);
          if (!cls) {
            invalid.push(reg_number);
            continue;
          }
          byClass[cls] += 1;
          inserts.push(
            env.DB.prepare(
              `INSERT INTO votes (id, created_at, class, reg_number, ballot_id)
               VALUES (?, ?, ?, ?, ?)`
            ).bind(crypto.randomUUID(), created_at, cls, reg_number, ballot_id)
          );
        }

        if (!inserts.length) {
          return bad("No valid registration numbers found");
        }

        await env.DB.batch(inserts);

        return json(
          {
            ok: true,
            inserted: inserts.length,
            invalid_reg_numbers: [...new Set(invalid)],
            by_class: byClass,
          },
          { headers: corsHeaders }
        );
      }

      // GET /api/tally
      if (req.method === "GET" && pathname === "/api/tally") {
        const rows = (
          await env.DB.prepare(
            `SELECT
               v.class,
               v.reg_number,
               r.name,
               r.car_year,
               r.car_make,
               r.car_model,
               r.car_color,
               COUNT(*) AS votes
             FROM votes v
             JOIN registrations r ON r.reg_number = v.reg_number
             GROUP BY
               v.class,
               v.reg_number,
               r.name,
               r.car_year,
               r.car_make,
               r.car_model,
               r.car_color
             ORDER BY v.class, votes DESC, v.reg_number ASC`
          ).all()
        ).results;

        return json({ ok: true, rows }, { headers: corsHeaders });
      }

      // POST /api/prizes/draw
      if (req.method === "POST" && pathname === "/api/prizes/draw") {
        const body = (await req.json().catch(() => null)) as any;
        if (!body) return bad("Invalid JSON");

        const prize_name = String(body.prize_name ?? "").trim();
        if (!prize_name) return bad("Prize name is required");

        const winner = await env.DB.prepare(
          `SELECT reg_number, name, car_year, car_make, car_model, car_color, class
           FROM registrations
           WHERE checked_in_at IS NOT NULL
             AND id NOT LIKE 'test-%'
             AND reg_number NOT IN (SELECT reg_number FROM prize_winners)
           ORDER BY RANDOM()
           LIMIT 1`
        ).first<any>();

        if (!winner) return bad("No eligible registrations (checked in and not already won)", 409);

        const id = crypto.randomUUID();
        await env.DB.prepare(
          `INSERT INTO prize_winners (id, created_at, prize_name, reg_number)
           VALUES (?, ?, ?, ?)`
        )
          .bind(id, isoNow(), prize_name, winner.reg_number)
          .run();

        return json({ ok: true, winner, prize_name }, { headers: corsHeaders });
      }

      // GET /api/prizes/winners
      if (req.method === "GET" && pathname === "/api/prizes/winners") {
        const rows = (
          await env.DB.prepare(
            `SELECT pw.created_at, pw.prize_name, pw.reg_number, r.name, r.car_year, r.car_make, r.car_model, r.car_color, r.class
             FROM prize_winners pw
             JOIN registrations r ON r.reg_number = pw.reg_number
             ORDER BY pw.created_at DESC`
          ).all()
        ).results;

        return json({ ok: true, rows }, { headers: corsHeaders });
      }

      // GET /api/admin/print/:reg  (printable fold sheet)
      {
        const m = match(pathname, /^\/api\/admin\/print\/(\d+)$/);
        if (req.method === "GET" && m) {
          const reg = toInt(m[1]);
          const r = await env.DB.prepare(`SELECT * FROM registrations WHERE reg_number = ?`).bind(reg).first<any>();
          if (!r) return bad("Not found", 404);

          const topTitle = `#${r.reg_number}`;
          const carLine = `${r.car_year} ${r.car_make} ${r.car_model}`;
          const colorLine = `Color: ${r.car_color}`;
          const classLine =
            `Class: ` +
            (r.class === "car_truck" ? "Car/Truck" : r.class === "motorcycle" ? "Motorcycle" : "Other");

          // Bottom half (edit as needed)
          const churchName = "Ridgeview Baptist Church";
          const churchIntro = "Thanks for coming out today. We would love to have you join us.";
          const churchTimes =
            "Service Times: Sunday School 10:00 AM | Worship 11:00 AM | Sunday Evening 6:00 PM | Wednesday 7:00 PM";
          const churchWeb = "ridgeviewbaptist.org";
          const churchAddr = "234 Hurd Road, Church Hill, TN 37642";
          const churchPhone = "423-357-4631";
          const siteBase = String(env.PUBLIC_SITE_URL || "").replace(/\/+$/, "");
          const backUrl = `${siteBase}/admin/detail.html?car=${encodeURIComponent(String(r.reg_number))}`;
          const backUrlJs = JSON.stringify(backUrl);

          const page = `<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>Registration ${escapeHtml(String(r.reg_number))}</title>
  <style>
    @page { size: letter; margin: 0.35in; }
    body { font-family: Arial, Helvetica, sans-serif; }
    .actions { display:flex; gap:8px; margin-bottom: 8px; }
    .btn { border: 1px solid #111; border-radius: 8px; padding: 6px 10px; background: #f5f5f5; cursor: pointer; text-decoration: none; color: #111; font-size: 13px; }
    .fold { border-top: 2px dashed #999; margin: 0.2in 0; }
    .top { height: 4.55in; display:flex; flex-direction:column; justify-content:center; align-items:center; }
    .num { font-size: 94px; font-weight: 800; line-height: 1; letter-spacing: -2px; }
    .car { font-size: 34px; font-weight: 700; margin-top: 8px; text-align:center; }
    .meta { font-size: 18px; margin-top: 8px; text-align:center; }
    .bottom { height: 4.55in; display:flex; flex-direction:column; justify-content:center; }
    .box { border: 2px solid #111; padding: 14px; border-radius: 10px; }
    .churchName { font-size: 24px; font-weight: 800; margin-bottom: 8px; }
    .churchText { font-size: 14px; margin: 5px 0; }
    .small { font-size: 14px; color: #333; }
    .row { display:flex; gap:18px; flex-wrap:wrap; margin-top:10px; }
    .pill { border: 1px solid #111; border-radius: 999px; padding: 6px 12px; font-size: 14px; }
    .admin { margin-top: 14px; font-size: 12px; color: #666; }
    @media print { .actions { display:none; } }
  </style>
</head>
<body>
  <div class="actions">
    <a class="btn" href="${escapeHtml(backUrl)}">Close</a>
    <button class="btn" onclick="window.print()">Print</button>
  </div>

  <div class="top box">
    <div class="num">${escapeHtml(topTitle)}</div>
    <div class="car">${escapeHtml(carLine)}</div>
    <div class="meta">${escapeHtml(colorLine)} | ${escapeHtml(classLine)}</div>
    <div class="admin">Registrant: ${escapeHtml(String(r.name))}</div>
  </div>

  <div class="fold"></div>

  <div class="bottom box">
    <div class="churchName">${escapeHtml(churchName)}</div>
    <div class="churchText">${escapeHtml(churchIntro)}</div>
    <div class="churchText">${escapeHtml(churchTimes)}</div>
    <div class="row">
      <div class="pill">${escapeHtml(churchWeb)}</div>
      <div class="pill">${escapeHtml(churchPhone)}</div>
    </div>
    <div class="churchText small" style="margin-top:12px;">${escapeHtml(churchAddr)}</div>
  </div>
  <script>
    (function () {
      const backUrl = ${backUrlJs};
      let triggered = false;

      function autoPrint() {
        if (triggered) return;
        triggered = true;
        window.print();
      }

      window.addEventListener("load", function () {
        setTimeout(autoPrint, 150);
      });

      window.addEventListener("afterprint", function () {
        window.location.href = backUrl;
      });
    })();
  </script>
</body>
</html>`;

          return html(page);
        }
      }


      // Default 404
      if (pathname === "/favicon.ico") return new Response(null, { status: 204 });

      return json({ ok: false, error: "Not found" }, { status: 404, headers: corsHeaders });
    } catch (err: any) {
      if (sentry) {
        sentry.captureException(err);
      }

      // Always respond (prevents hang)
      return json(
        { ok: false, error: "Unhandled error" },
        { status: 500, headers: corsHeaders }
      );
    }
  },
};
