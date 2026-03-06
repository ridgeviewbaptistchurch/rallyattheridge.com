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
| `AUTH_SECRET` | Wrangler secret | HMAC key for signing session cookies |
| `SENTRY_DSN` | Wrangler secret (optional) | Sentry error tracking DSN |
| `SENTRY_ENVIRONMENT` | Wrangler secret (optional) | e.g. `production` |

To set a secret:

```bash
cd api
npx wrangler secret put AUTH_SECRET
```

#### Creating an admin user

Use the tool in `api/tools/make-user.mjs` to generate the SQL for a new admin user, then insert it into the database:

```bash
node api/tools/make-user.mjs
# follow the prompts, then run the output SQL with wrangler d1 execute
```

## Admin panel

The admin panel lives at `/admin/` and requires a login. Features:

- **Search** — look up registrations by car number, name, phone, email, or make/model
- **Register** — on-site registration that auto-checks the vehicle in and opens a print sheet
- **Votes** — enter people's choice votes by car number
- **Drawings** — draw random door prize winners from checked-in attendees

## Tech stack

- **Frontend**: Plain HTML, CSS, vanilla JS. Bootstrap 5 for admin pages only.
- **Backend**: Cloudflare Workers (TypeScript), Cloudflare D1 (SQLite), Wrangler
- **Error tracking**: Sentry via `toucan-js`
- **Auth**: PBKDF2 password hashing, HMAC-signed session cookies
