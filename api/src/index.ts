type Env = {
  DB: D1Database;
  PUBLIC_SITE_URL: string;
  AUTH_SECRET: string;
};

const SESSION_COOKIE = "carshow_sess";
const SESSION_TTL_SECONDS = 60 * 60 * 12; // 12 hours
const MAX_PBKDF2_ITERS = 100000;

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

function setCookieHeader(value: string): string {
  // Secure must be on for HTTPS (Workers is HTTPS). SameSite=Lax is fine for this.
  return `${SESSION_COOKIE}=${encodeURIComponent(value)}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${SESSION_TTL_SECONDS}`;
}

function clearCookieHeader(): string {
  return `${SESSION_COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`;
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

  if (origin) {
    headers["access-control-allow-origin"] = origin;
    headers["access-control-allow-credentials"] = "true";
  } else {
    headers["access-control-allow-origin"] = "*";
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

async function nextRegNumber(db: D1Database): Promise<number> {
  const r = await db.prepare("SELECT COALESCE(MAX(reg_number), 0) AS m FROM registrations").first<{ m: number }>();
  return (r?.m ?? 0) + 1;
}

function match(pathname: string, pattern: RegExp): RegExpExecArray | null {
  return pattern.exec(pathname);
}

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    const corsHeaders = corsHeadersFor(req);
    try {
      const url = new URL(req.url);
      const { pathname } = url;
      const bad = (message: string, status = 400) =>
        json({ ok: false, error: message }, { status, headers: corsHeaders });

      // CORS preflight
      if (req.method === "OPTIONS" && pathname.startsWith("/api/")) {
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
        const body = (await req.json().catch(() => null)) as any;
        if (!body) return bad("Invalid JSON");

        const username = normalize(body.username).toLowerCase();
        const password = String(body.password ?? "");

        if (!username || !password) return bad("Username and password required");

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
              "set-cookie": setCookieHeader(sess),
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
              "set-cookie": clearCookieHeader(),
            },
          }
        );
      }

      const isProtectedApi =
        (pathname.startsWith("/api/admin/") && pathname !== "/api/admin/login") ||
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



      // POST /api/register
      if (req.method === "POST" && pathname === "/api/register") {
        const body = (await req.json().catch(() => null)) as any;
        if (!body) return bad("Invalid JSON");

        const name = normalize(body.name);
        const email = normalize(body.email);
        const phone = normalize(body.phone);

        const car_year = normalize(body.car_year);
        const car_make = normalize(body.car_make);
        const car_model = normalize(body.car_model);
        const car_color = normalize(body.car_color);

        const cls = requireClass(body.class);

        if (!name) return bad("Name is required");
        if (!car_year || !car_make || !car_model || !car_color) return bad("Car year/make/model/color are required");
        if (!cls) return bad("Class is required");

        const reg_number = await nextRegNumber(env.DB);
        const id = crypto.randomUUID();
        const created_at = isoNow();

        await env.DB.prepare(
          `INSERT INTO registrations
           (id, reg_number, created_at, name, email, phone, car_year, car_make, car_model, car_color, class)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
        )
          .bind(
            id,
            reg_number,
            created_at,
            name,
            email || null,
            phone || null,
            car_year,
            car_make,
            car_model,
            car_color,
            cls
          )
          .run();

        return json(
          {
            ok: true,
            reg_number,
            id,
            print_url: `${env.PUBLIC_SITE_URL}/admin/print.html?car=${reg_number}`,
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
               ORDER BY reg_number DESC
               LIMIT 50`
            ).bind(maybeNum, qLike, qLike, qLike)
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

      // GET /api/admin/registration/:reg
      {
        const m = match(pathname, /^\/api\/admin\/registration\/(\d+)$/);
        if (req.method === "GET" && m) {
          const reg = toInt(m[1]);
          const row = await env.DB.prepare(`SELECT * FROM registrations WHERE reg_number = ?`).bind(reg).first();
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

        const cls = requireClass(body.class);
        if (!cls) return bad("Class is required");

        const reg_number = toInt(body.reg_number);
        if (!Number.isFinite(reg_number)) return bad("Invalid reg number");

        const exists = await env.DB.prepare(
          `SELECT reg_number FROM registrations WHERE reg_number = ? AND class = ?`
        )
          .bind(reg_number, cls)
          .first();

        if (!exists) return bad("Registration not found for that class");

        const id = crypto.randomUUID();
        const created_at = isoNow();
        const ballot_id = String(body.ballot_id ?? "").trim() || null;

        await env.DB.prepare(
          `INSERT INTO votes (id, created_at, class, reg_number, ballot_id)
           VALUES (?, ?, ?, ?, ?)`
        )
          .bind(id, created_at, cls, reg_number, ballot_id)
          .run();

        return json({ ok: true }, { headers: corsHeaders });
      }

      // GET /api/tally
      if (req.method === "GET" && pathname === "/api/tally") {
        const rows = (
          await env.DB.prepare(
            `SELECT class, reg_number, COUNT(*) AS votes
             FROM votes
             GROUP BY class, reg_number
             ORDER BY class, votes DESC, reg_number ASC`
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

          const page = `<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>Registration ${escapeHtml(String(r.reg_number))}</title>
  <style>
    @page { size: letter; margin: 0.5in; }
    body { font-family: Arial, Helvetica, sans-serif; }
    .fold { border-top: 2px dashed #999; margin: 0.35in 0; }
    .top { height: 5.0in; display:flex; flex-direction:column; justify-content:center; align-items:center; }
    .num { font-size: 110px; font-weight: 800; line-height: 1; letter-spacing: -2px; }
    .car { font-size: 40px; font-weight: 700; margin-top: 10px; text-align:center; }
    .meta { font-size: 22px; margin-top: 10px; text-align:center; }
    .bottom { height: 5.0in; display:flex; flex-direction:column; justify-content:center; }
    .box { border: 2px solid #111; padding: 14px; border-radius: 10px; }
    .churchName { font-size: 28px; font-weight: 800; margin-bottom: 10px; }
    .churchText { font-size: 16px; margin: 6px 0; }
    .small { font-size: 14px; color: #333; }
    .row { display:flex; gap:18px; flex-wrap:wrap; margin-top:10px; }
    .pill { border: 1px solid #111; border-radius: 999px; padding: 6px 12px; font-size: 14px; }
    .admin { margin-top: 14px; font-size: 12px; color: #666; }
    @media print { button { display:none; } }
  </style>
</head>
<body>
  <button onclick="window.print()">Print</button>

  <div class="top box">
    <div class="num">${escapeHtml(topTitle)}</div>
    <div class="car">${escapeHtml(carLine)}</div>
    <div class="meta">${escapeHtml(colorLine)} | ${escapeHtml(classLine)}</div>
    <div class="admin">Registrant: ${escapeHtml(String(r.name))}${r.phone ? " | " + escapeHtml(String(r.phone)) : ""}</div>
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
</body>
</html>`;

          return html(page);
        }
      }

      // Default 404
      if (pathname === "/favicon.ico") return new Response(null, { status: 204 });

      return json({ ok: false, error: "Not found" }, { status: 404, headers: corsHeaders });
    } catch (err: any) {
      // Always respond (prevents hang)
      return json(
        { ok: false, error: "Unhandled error", detail: String(err?.stack || err) },
        { status: 500, headers: corsHeaders }
      );
    }
  },
};
