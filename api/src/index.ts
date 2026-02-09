import { Router } from "itty-router";

type Env = {
  DB: D1Database;
  PUBLIC_SITE_URL: string;
};

const router = Router();

router.options("/api/*", () => {
  return new Response(null, {
    status: 204,
    headers: {
      "access-control-allow-origin": "*",
      "access-control-allow-methods": "GET,POST,OPTIONS",
      "access-control-allow-headers": "content-type",
    },
  });
});


// Helpers
const json = (data: unknown, init: ResponseInit = {}) =>
  new Response(JSON.stringify(data), {
    ...init,
    headers: { "content-type": "application/json; charset=utf-8", ...(init.headers || {}) },
  });

const bad = (message: string, status = 400) => json({ ok: false, error: message }, { status });

const isoNow = () => new Date().toISOString();

const toInt = (v: unknown) => {
  const n = Number(v);
  return Number.isFinite(n) ? Math.trunc(n) : NaN;
};

const escapeHtml = (s: string) =>
  s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");

async function nextRegNumber(db: D1Database): Promise<number> {
  const r = await db.prepare("SELECT COALESCE(MAX(reg_number), 0) AS m FROM registrations").first<{ m: number }>();
  return (r?.m ?? 0) + 1;
}

function requireClass(c: unknown): "car_truck" | "motorcycle" | "other" | null {
  if (c === "car_truck" || c === "motorcycle" || c === "other") return c;
  return null;
}

function normalizeName(s: unknown): string {
  return String(s ?? "").trim();
}

// Health
router.get("/api/health", () => json({ ok: true }));

// Public registration
router.post("/api/register", async (req: Request, env: Env) => {
  const body = await req.json().catch(() => null) as any;
  if (!body) return bad("Invalid JSON");

  const name = normalizeName(body.name);
  const email = normalizeName(body.email);
  const phone = normalizeName(body.phone);

  const car_year = normalizeName(body.car_year);
  const car_make = normalizeName(body.car_make);
  const car_model = normalizeName(body.car_model);
  const car_color = normalizeName(body.car_color);

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
  ).bind(id, reg_number, created_at, name, email || null, phone || null, car_year, car_make, car_model, car_color, cls).run();

  return json({
    ok: true,
    reg_number,
    id,
    print_url: `${env.PUBLIC_SITE_URL}/admin/print.html?car=${reg_number}`
  });
});

// Admin search
router.get("/api/admin/search", async (req: Request, env: Env) => {
  const url = new URL(req.url);
  const q = (url.searchParams.get("q") ?? "").trim();
  if (!q) return json({ ok: true, results: [] });

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
  return json({ ok: true, results });
});

// Admin registration detail
router.get("/api/admin/registration/:reg", async (req: any, env: Env) => {
  const reg = toInt(req.params.reg);
  if (!Number.isFinite(reg)) return bad("Invalid reg number");

  const row = await env.DB.prepare(
    `SELECT * FROM registrations WHERE reg_number = ?`
  ).bind(reg).first();

  if (!row) return bad("Not found", 404);
  return json({ ok: true, registration: row });
});

// Check-in
router.post("/api/admin/registration/:reg/checkin", async (req: any, env: Env) => {
  const reg = toInt(req.params.reg);
  if (!Number.isFinite(reg)) return bad("Invalid reg number");

  const now = isoNow();
  const r = await env.DB.prepare(
    `UPDATE registrations
     SET checked_in_at = COALESCE(checked_in_at, ?)
     WHERE reg_number = ?`
  ).bind(now, reg).run();

  return json({ ok: true, updated: r.meta.changes });
});

// Votes
router.post("/api/votes", async (req: Request, env: Env) => {
  const body = await req.json().catch(() => null) as any;
  if (!body) return bad("Invalid JSON");

  const cls = requireClass(body.class);
  if (!cls) return bad("Class is required");

  const reg_number = toInt(body.reg_number);
  if (!Number.isFinite(reg_number)) return bad("Invalid reg number");

  // Optional: ensure the car exists AND matches class
  const exists = await env.DB.prepare(
    `SELECT reg_number FROM registrations WHERE reg_number = ? AND class = ?`
  ).bind(reg_number, cls).first();

  if (!exists) return bad("Registration not found for that class");

  const id = crypto.randomUUID();
  const created_at = isoNow();
  const ballot_id = String(body.ballot_id ?? "").trim() || null;

  await env.DB.prepare(
    `INSERT INTO votes (id, created_at, class, reg_number, ballot_id)
     VALUES (?, ?, ?, ?, ?)`
  ).bind(id, created_at, cls, reg_number, ballot_id).run();

  return json({ ok: true });
});

// Tally
router.get("/api/tally", async (_req: Request, env: Env) => {
  const rows = (await env.DB.prepare(
    `SELECT class, reg_number, COUNT(*) AS votes
     FROM votes
     GROUP BY class, reg_number
     ORDER BY class, votes DESC, reg_number ASC`
  ).all()).results;

  return json({ ok: true, rows });
});

// Door prize draw
router.post("/api/prizes/draw", async (req: Request, env: Env) => {
  const body = await req.json().catch(() => null) as any;
  if (!body) return bad("Invalid JSON");

  const prize_name = String(body.prize_name ?? "").trim();
  if (!prize_name) return bad("Prize name is required");

  // Pick random checked-in reg_number excluding prior winners
  // SQLite random(): ORDER BY RANDOM()
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
  ).bind(id, isoNow(), prize_name, winner.reg_number).run();

  return json({ ok: true, winner, prize_name });
});

router.get("/api/prizes/winners", async (_req: Request, env: Env) => {
  const rows = (await env.DB.prepare(
    `SELECT pw.created_at, pw.prize_name, pw.reg_number, r.name, r.car_year, r.car_make, r.car_model, r.car_color, r.class
     FROM prize_winners pw
     JOIN registrations r ON r.reg_number = pw.reg_number
     ORDER BY pw.created_at DESC`
  ).all()).results;

  return json({ ok: true, rows });
});

// Printable full-page HTML (fold in half)
router.get("/api/admin/print/:reg", async (req: any, env: Env) => {
  const reg = toInt(req.params.reg);
  if (!Number.isFinite(reg)) return bad("Invalid reg number");

  const r = await env.DB.prepare(`SELECT * FROM registrations WHERE reg_number = ?`).bind(reg).first<any>();
  if (!r) return bad("Not found", 404);

  const topTitle = `#${r.reg_number}`;
  const carLine = `${r.car_year} ${r.car_make} ${r.car_model}`;
  const colorLine = `Color: ${r.car_color}`;
  const classLine = `Class: ${r.class === "car_truck" ? "Car/Truck" : r.class === "motorcycle" ? "Motorcycle" : "Other"}`;

  // Customize this bottom section text to match your church info
  const churchName = "Ridgeview Baptist Church";
  const churchIntro = "Thanks for coming out today. We would love to have you join us.";
  const churchTimes = "Service Times: Sunday Worship 8:30 AM | Sunday School 9:30 AM | Worship 10:30 AM | Wednesday 6:30 PM";
  const churchWeb = "ridgeviewbaptist.org";
  const churchAddr = "234 Hurd Road, Church Hill, TN 37642";
  const churchPhone = "423-357-4631";

  const html = `<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>Registration ${escapeHtml(String(r.reg_number))}</title>
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <style>
    @page { size: letter; margin: 0.5in; }
    body { font-family: Arial, Helvetica, sans-serif; }
    .page { width: 100%; }
    .fold { border-top: 2px dashed #999; margin: 0.35in 0; }
    .top { height: 5.0in; display: flex; flex-direction: column; justify-content: center; align-items: center; }
    .num { font-size: 110px; font-weight: 800; line-height: 1; letter-spacing: -2px; }
    .car { font-size: 40px; font-weight: 700; margin-top: 10px; text-align: center; }
    .meta { font-size: 22px; margin-top: 10px; text-align: center; }
    .bottom { height: 5.0in; display: flex; flex-direction: column; justify-content: center; }
    .churchName { font-size: 28px; font-weight: 800; margin-bottom: 10px; }
    .churchText { font-size: 16px; margin: 6px 0; }
    .small { font-size: 14px; color: #333; }
    .box { border: 2px solid #111; padding: 14px; border-radius: 10px; }
    .row { display: flex; gap: 18px; flex-wrap: wrap; }
    .pill { border: 1px solid #111; border-radius: 999px; padding: 6px 12px; font-size: 14px; }
    .admin { margin-top: 14px; font-size: 12px; color: #666; }
    @media print {
      button { display: none; }
      a { color: inherit; text-decoration: none; }
    }
  </style>
</head>
<body>
  <button onclick="window.print()">Print</button>

  <div class="page">
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
      <div class="row" style="margin-top:10px;">
        <div class="pill">${escapeHtml(churchWeb)}</div>
        <div class="pill">${escapeHtml(churchPhone)}</div>
      </div>
      <div class="churchText small" style="margin-top:12px;">${escapeHtml(churchAddr)}</div>
    </div>
  </div>
</body>
</html>`;

  return new Response(html, { headers: { "content-type": "text/html; charset=utf-8" } });
});

router.get("/", () =>
  new Response(
    "Car Show API is running. Try /api/health",
    { headers: { "content-type": "text/plain; charset=utf-8" } }
  )
);

router.all("*", () => bad("Not found", 404));

export default {
  fetch: (req: Request, env: Env, ctx: ExecutionContext) => router.handle(req, env, ctx),
};
