# Nexus Workspaces — Senior Supabase Backend

Multi-tenant B2B collaboration backend for the Senior Supabase Developer Technical Assessment.

PostgreSQL is the security boundary. The frontend is treated as hostile: clients can call the API, Storage, Realtime, and RPCs directly.

## Quick start

From a clone of this repository, with Docker Desktop running:

```bash
# 1. CLI (pick one)
npm install -g supabase          # or: scoop install supabase / brew install supabase
supabase --version

# 2. Start the local stack (first run downloads several GB of images)
cd <this-repo>
supabase start
supabase db reset

# 3. Database / RLS tests (no extra Docker images)
# Windows:
powershell -File scripts/run_db_tests.ps1
# macOS / Linux:
bash scripts/run_db_tests.sh
```

Then open Studio: [http://127.0.0.1:54323](http://127.0.0.1:54323)

Sign in with any seeded user, password `password` (see table below).

Stop later with `supabase stop`.

## Prerequisites

| Tool | Why |
| --- | --- |
| [Docker Desktop](https://docs.docker.com/desktop/) | Required. The stack is Postgres, Auth, Storage, Realtime, Kong. |
| [Supabase CLI](https://supabase.com/docs/guides/local-development/cli) | `supabase start`, `db reset`, `status`, `functions serve`. |
| Node.js 22+ | Only for `npm run test:http` and Edge Function helper scripts. |

First `supabase start` pulls a multi-GB image set onto **the disk that holds Docker data**, not this git repo. If that disk is almost full, move Docker’s disk image **before** start: Settings → Resources → Advanced → Disk image location. Docker always appends `\DockerDesktop` to the folder you choose.

## Local setup

```bash
supabase start
supabase db reset
```

`db reset` applies every file in `supabase/migrations/` in filename order, then loads `supabase/seed.sql`.

`supabase status` prints local URLs and keys (anon / service_role). Those keys are **local demo values only**. Never commit them.

| Service | URL |
| --- | --- |
| API (Kong) | http://127.0.0.1:54321 |
| Studio | http://127.0.0.1:54323 |
| Inbucket (local mail catcher) | http://127.0.0.1:54324 |
| Database (host) | `postgresql://postgres:postgres@127.0.0.1:54322/postgres` |

The Postgres Docker name is `supabase_db_supabase` (`project_id` in `supabase/config.toml`). Test scripts assume that name.

## Tests

### Database / RLS (required)

pgTAP is already in the local Postgres image. These scripts **do not** pull the `pg_prove` image:

```powershell
powershell -File scripts/run_db_tests.ps1
```

```bash
bash scripts/run_db_tests.sh
```

You should see all of `01`–`05` finish with `ok` rows and `All database tests completed.`

Equivalent:

```bash
docker exec -i supabase_db_supabase psql -U postgres < supabase/tests/01_adversarial.sql
docker exec -i supabase_db_supabase psql -U postgres < supabase/tests/02_confidential.sql
docker exec -i supabase_db_supabase psql -U postgres < supabase/tests/03_storage.sql
docker exec -i supabase_db_supabase psql -U postgres < supabase/tests/04_addendum.sql
docker exec -i supabase_db_supabase psql -U postgres < supabase/tests/05_requirement.sql
```

`supabase test db` also works if you are willing to pull the extra `pg_prove` image.

### API / Storage / Realtime (optional, needs Node)

```bash
npm install
```

Copy keys from `supabase status` (do not commit them):

```powershell
$env:SUPABASE_URL="http://127.0.0.1:54321"
$env:SUPABASE_ANON_KEY="<anon or publishable key>"
$env:SUPABASE_SERVICE_ROLE_KEY="<service_role key>"
$env:WEBHOOK_SECRET="replace-with-a-long-random-secret"
npm run test:http
```

```bash
export SUPABASE_URL=http://127.0.0.1:54321
export SUPABASE_ANON_KEY="<anon or publishable key>"
export SUPABASE_SERVICE_ROLE_KEY="<service_role key>"
export WEBHOOK_SECRET=replace-with-a-long-random-secret
npm run test:http
```

This checks HMAC construction, invite RPC authz, concurrent invitation accept, webhook idempotency, Storage MIME allow/deny, and Realtime isolation. It does **not** start `supabase functions serve`.

## Environment variables

Never commit real secrets. Local names:

```
SUPABASE_URL=http://127.0.0.1:54321
SUPABASE_ANON_KEY=<from supabase status>
SUPABASE_SERVICE_ROLE_KEY=<from supabase status>
WEBHOOK_SECRET=replace-with-a-long-random-secret
SITE_URL=http://127.0.0.1:3000
```

For Edge Functions:

```bash
cp supabase/functions/.env.example supabase/functions/.env
```

`WEBHOOK_SECRET` in that file must match the value you use when signing webhook requests.

## Edge Functions

Needs extra disk the first time (`supabase/edge-runtime` image).

```bash
cp supabase/functions/.env.example supabase/functions/.env
supabase functions serve
```

In another terminal, get a user JWT (seeded owner):

```bash
curl -s -X POST "http://127.0.0.1:54321/auth/v1/token?grant_type=password" \
  -H "apikey: $SUPABASE_ANON_KEY" \
  -H "Content-Type: application/json" \
  -d '{"email":"a-owner@example.com","password":"password"}'
```

Use `access_token` from that JSON:

```bash
curl -X POST http://127.0.0.1:54321/functions/v1/invite-member \
  -H "Authorization: Bearer <USER_ACCESS_TOKEN>" \
  -H "apikey: $SUPABASE_ANON_KEY" \
  -H "Content-Type: application/json" \
  -d "{\"organisation_id\":\"a0000000-0000-0000-0000-0000000000a1\",\"email\":\"new@example.com\",\"role\":\"member\"}"
```

`invite-member` uses the **caller JWT** and `create_invitation` (no service role). A second invite for the same pending email upserts token hash and expiry instead of inserting another row.

Webhook — HMAC over `timestamp + '.' + rawBody`, verified **before** JSON parse:

```bash
# signature = hex(hmac_sha256(WEBHOOK_SECRET, "${timestamp}.${raw}"))
curl -X POST http://127.0.0.1:54321/functions/v1/external-webhook \
  -H "apikey: $SUPABASE_ANON_KEY" \
  -H "x-nexus-signature: sha256=<hex>" \
  -H "x-nexus-timestamp: <unix-seconds>" \
  -H "x-nexus-event-id: evt_123" \
  -H "x-nexus-event-type: ping" \
  --data-binary '{"ok":true}'
```

Invalid signature → 401 and no RPC. Duplicate `event_id` → 200 `{ "status": "duplicate" }` and a single `webhook_events` row.

Helper (same keys as `test:http`):

```powershell
node scripts/invoke_edge.mjs
```

Production email: send the raw invite token out of band. Do not log it. `invite_url` is development-only.

## Seeded users

Password for every seeded user: `password`

| Email | Role | Tenant |
| --- | --- | --- |
| a-owner@example.com | owner | Organization A |
| a-admin@example.com | admin | Organization A |
| a-member@example.com | member | Organization A |
| a-guest@example.com | guest | Organization A |
| a-manager@example.com | project manager | Org A normal project |
| a-contributor@example.com | contributor | Org A normal project |
| a-viewer@example.com | viewer | Org A normal project |
| b-owner@example.com | owner | Organization B |
| b-admin@example.com | admin | Organization B |
| invitee@example.com | pending invite | Organization A |

Known invitation token (tests / `db reset` only):

`0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef`

Suggested Studio check: sign in as `a-admin@example.com` and confirm the **confidential** project is hidden until that admin is added to `project_memberships`. Sign in as `b-owner@example.com` and confirm Org A task UUIDs return no rows.

## Documentation

- `ARCHITECTURE.md` — data model, authz, privileged boundaries, confidential-project change, deletion policy
- `SECURITY.md` — threat model, privileges, residual risks
- `PERFORMANCE.md` — indexes, five `EXPLAIN (ANALYZE, BUFFERS)` plans, omitted index

Optional large local volume (tens of GB free on the Docker data disk):

```bash
docker exec -i supabase_db_supabase psql -U postgres < scripts/perf_load.sql
docker exec -i supabase_db_supabase psql -U postgres < scripts/perf_explain.sql
```

## Intentional decisions

- Roles/status use `TEXT + CHECK`, not PostgreSQL ENUMs
- Project access is centralized in `app_hidden.can_view_project` (SQL, Storage, Realtime)
- Confidential projects change those helpers (plus Storage delete via `can_delete_project_file`)
- Invitation tokens are stored as SHA-256 digests only
- Audit and webhook tables have no client INSERT/UPDATE/DELETE
- Database tests run inside `supabase_db_supabase` so a clone is not forced to pull `pg_prove`

## Deviations from the brief

These are deliberate, not missing features:

- **Test runner:** the brief allows pgTAP *or* client tests. We use pgTAP **inside** the already-running Postgres container (`scripts/run_db_tests.*`) instead of `supabase test db`, so a clone does not have to pull a separate `pg_prove` image.
- **Large seed volume:** the brief asks for 100k tasks / 500k comments *if the environment permits*. Indexes and `EXPLAIN` plans are documented; the generator is `scripts/perf_load.sql` for machines with spare Docker disk.
- **Edge Function HTTP gateway:** `invite-member` and `external-webhook` source is in the repo and is the required implementation. Live `supabase functions serve` needs an extra image; HMAC/RPC/Storage/Realtime contracts are also covered by `npm run test:http` without that image.

## Migrations (local → production)

Local: `supabase db reset` = migrations + `seed.sql`.

Staging/production: `supabase db push` (or CI) against a linked project. Do not edit production schema in the Dashboard. A risky change is its own migration, applied in a window, and rolled **forward** with a follow-up migration if it fails after partial apply — not `db reset` on production.

## AI disclosure

Implementation was assisted by an AI coding agent. Every security decision must be explainable in the walkthrough.

## Incomplete / optional

- **100k tasks / 500k comments** were not loaded in the original authoring environment (Docker data disk nearly full). Indexes and five query plans are in `PERFORMANCE.md`. Run `scripts/perf_load.sql` if your Docker disk allows it.
- **`supabase functions serve`** was not left running there (edge-runtime image pull). Function source, SQL RPCs, and `npm run test:http` cover the security contracts. Serve the functions when you have disk if you want the HTTP gateway walkthrough.
