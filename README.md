# Rally at the Ridge

Car show registration and admin system for the annual Rally at the Ridge event at Ridgeview Baptist Church.

## Project Structure

```
rallyattheridge.com/
├── api/          # Cloudflare Worker (TypeScript) — backend API + D1 database
└── site/         # Static HTML/CSS/JS — public site and admin panel
```

## Two separate deployments

### `site/` — Static site via GitHub to Cloudflare Pages

The `site/` folder is a plain static site (no build step). It is deployed automatically via the `rallyattheridge-com` Cloudflare Pages project connected to this GitHub repository.

- Public site: `https://rallyattheridge.org/`
- Admin panel: `https://rallyattheridge.org/admin/`
- Registration: `https://rallyattheridge.org/register/`

Pushes to `main` trigger an automatic redeploy through the Cloudflare Pages GitHub integration. The root directory for the Pages project should be set to `site`.

### `api/` — Cloudflare Worker via Wrangler

The `api/` folder is a Cloudflare Worker (`carshow-api`). It is deployed manually from your local machine using Wrangler — it is **not** auto-deployed via GitHub.

Live API: `https://api.rallyattheridge.org`

#### First-time / local setup

```bash
cd api
npm install
npx wrangler login
```

#### Local development

```bash
cd api
npm run dev
```

This starts a local worker at `http://localhost:8787`. The public registration form and admin pages point to the production API by default — to develop locally you would need to temporarily change `API_BASE` in the relevant HTML files.

#### Deploy to production

```bash
cd api
npm run deploy
```

#### Database (D1)

The API uses a Cloudflare D1 SQLite database. The schema is in `api/schema.sql`.

To apply the schema to the production database:

```bash
cd api
npx wrangler d1 execute carshow_db --remote --file=schema.sql
```

To apply a migration:

```bash
cd api
npx wrangler d1 execute carshow_db --remote --file=migrations/<filename>.sql
```

To query the production database directly:

```bash
npx wrangler d1 execute carshow_db --remote --command="SELECT COUNT(*) FROM registrations"
```

#### Environment variables / secrets

| Variable | Where set | Description |
|---|---|---|
| `PUBLIC_SITE_URL` | `wrangler.toml` `[vars]` | Base URL of the static site |
| `SENDER_FROM_EMAIL` | `wrangler.toml` `[vars]` | From address for transactional emails |
| `SENDER_FROM_NAME` | `wrangler.toml` `[vars]` | From name for transactional emails |
| `SENDER_TEMPLATE_CONFIRMATION` | `wrangler.toml` `[vars]` | Sender.net template ID for the registration confirmation email |
| `SENDER_GROUP_ID` | `wrangler.toml` `[vars]` | Sender.net group ID to subscribe registrants to (see below) |
| `ADMIN_EMAILS` | `wrangler.toml` `[vars]` | Comma-separated list of admin emails for weekly summary |
| `SHOW_DATE` | `wrangler.toml` `[vars]` | Event date string, e.g. `April 25, 2026` |
| `AUTH_SECRET` | Wrangler secret | HMAC key for signing session cookies |
| `SENDER_API_KEY` | Wrangler secret | Sender.net transactional API key |
| `CRON_SECRET` | Wrangler secret | Bearer token for external cron callers (weekly summary, reminders) |
| `SENTRY_DSN` | Wrangler secret (optional) | Sentry error tracking DSN |
| `SENTRY_ENVIRONMENT` | Wrangler secret (optional) | e.g. `production` |

To set a secret:

```bash
cd api
npx wrangler secret put AUTH_SECRET
```

#### Email (Sender.net)

Transactional emails are sent via [Sender.net](https://www.sender.net/). Three email flows are supported:

| Flow | Trigger | Description |
|---|---|---|
| Confirmation | Public or admin registration (if email provided) | Sent via `ctx.waitUntil()` immediately after registration |
| Weekly summary | `POST /api/admin/email/weekly-summary` | Summary of registrations; auth via session cookie or `Authorization: Bearer <CRON_SECRET>` |
| Reminders | `POST /api/admin/email/reminders` | Reminder emails to registrants; supports `?dry_run=true` to preview count without sending |

The weekly summary and reminder endpoints accept either a logged-in admin session cookie **or** an `Authorization: Bearer <CRON_SECRET>` header, making them safe to call from an external cron service.

**Group subscription**: When a registrant provides an email address, they are also subscribed to the Sender.net group specified by `SENDER_GROUP_ID`. This uses the `POST https://api.sender.net/v2/subscribers` endpoint. To find your group ID:

```bash
curl -H "Authorization: Bearer <SENDER_API_KEY>" https://api.sender.net/v2/groups
```

Then set `SENDER_GROUP_ID` in `wrangler.toml`.

#### Creating an admin user

Use the tool in `api/tools/make-user.mjs` to generate a hashed password and INSERT SQL, then run it against the database:

```bash
cd api
node tools/make-user.mjs <username> <password>
```

Copy the `INSERT INTO users ...` line from the output, then execute it:

```bash
npx wrangler d1 execute carshow_db --remote --command="INSERT INTO users ..."
```

Running the script again for the same username will update the password (upsert).

#### Test registrations

The migration `api/migrations/2026-03-10_test_users.sql` inserts 10 seed registrations with IDs prefixed `test-`. These are excluded from admin stats counts and from prize drawings so they don't skew real numbers.

## Admin panel

The admin panel lives at `/admin/` and requires a login. Features:

- **Search** — look up registrations by car number, name, phone, email, or make/model
- **Register** — on-site registration that auto-checks the vehicle in and opens a print sheet
- **Votes** — enter people's choice votes by car number
- **Drawings** — draw random door prize winners from checked-in attendees

## Tech stack

- **Frontend**: Plain HTML, CSS, vanilla JS. Bootstrap 5 for admin pages only.
- **Backend**: Cloudflare Workers (TypeScript), Cloudflare D1 (SQLite), Wrangler
- **Email**: Sender.net transactional API
- **Error tracking**: Sentry via `toucan-js`
- **Auth**: PBKDF2 password hashing, HMAC-signed session cookies
