# Architecture

Nexus Workspaces is a multi-tenant collaboration backend. PostgreSQL is the security and integrity boundary. Supabase Auth, Storage, Realtime, and Edge Functions sit on top of that boundary; they must not become an RLS bypass.

## Entity relationships

```
auth.users 1—1 profiles
organisations 1—N organisation_memberships N—1 profiles
organisations 1—N projects
projects 1—N project_memberships N—1 profiles
projects 1—N tasks 1—N comments
projects 1—N project_files / storage objects
organisations 1—N invitations
organisations 1—N audit_events
webhook_events (global idempotency store)
```

A project belongs to exactly one organisation. Moving a project or task across organisations is rejected by triggers plus `WITH CHECK` and column-level grants.

## Role model

Organisation: `owner | admin | member | guest`  
Project: `manager | contributor | viewer`

Roles are `TEXT + CHECK`, not ENUM. Adding a value is a constraint swap, not a table rewrite. Invalid values fail writes immediately.

One active owner per organisation is enforced with a partial unique index.

## Authorisation

Client identity is `auth.uid()` / `auth.jwt()->>'email'`. Client-supplied `user_id`, `organisation_id`, `project_id`, `role`, `is_admin`, and `is_owner` are never trusted.

Membership checks run in `app_hidden` `SECURITY DEFINER` helpers with a fixed `search_path`. Those helpers read membership tables without going through RLS, which avoids recursive policy evaluation.

Public wrappers:

- `public.can_view_project(uuid)` — used by SQL RLS, Storage, and Realtime

Baseline (before confidential migration): owner/admin of the org, or explicit project membership.

After confidential migration: owner always; admin only for `access_mode = 'normal'` unless explicitly a project member.

SQL RLS, Storage SELECT/INSERT, and Realtime all call `can_view_project`. Storage DELETE uses `can_delete_project_file`, which reuses that same view check for org admins. The confidential rule is not copied into each table policy.

## Where logic belongs

| Concern | Location | Why |
| --- | --- | --- |
| Row visibility / mutation | RLS | Hostile clients hit PostgREST directly |
| Multi-row atomic changes | SQL functions | Invitation accept, ownership transfer, task version bump + audit |
| Token generation / HTTP | Edge Function `invite-member` | Needs crypto and a user JWT; no service role until authorised |
| Third-party webhook | Edge Function `external-webhook` | Raw-body HMAC; no user JWT |
| File bytes | Storage RLS | Same `can_view_project` decision |
| Live updates | Realtime Broadcast | Private topic `project:<id>` |

## Privileged functions

`SECURITY INVOKER` is the default. `SECURITY DEFINER` is used for:

- `app_hidden` authz helpers (must read memberships without RLS recursion)
- `create_profile_for_new_user` (write profile on `auth.users` insert)
- `accept_invitation`, `transfer_organisation_ownership`, `transition_task`, `create_invitation`, `record_webhook_event`, `app_hidden.write_audit`

Each definer function sets a locked `search_path` (`pg_catalog, public`, plus `extensions` only on `accept_invitation` so `digest()` resolves), uses qualified names, validates `auth.uid()`, and has `EXECUTE` revoked from `PUBLIC`.

Ownership transfer: current owner only; target must be an active member; previous owner becomes `admin`; transaction-level advisory lock; audit row in the same transaction.

Invitation identity policy: the authenticated JWT email must match the invitation email (lowercased). Tokens are SHA-256 digests. `SELECT FOR UPDATE` plus `accepted_at` prevents double accept under concurrency.

Webhook strategy: Edge Function verifies HMAC on `timestamp + '.' + rawBody` before parse; `record_webhook_event` is `service_role` only and is unique on `(provider, event_id)`.

Concurrency: invitation accept and ownership transfer take row/advisory locks in one transaction with the audit write. Task updates use optimistic `version` (`40001` on stale).

Task field-level rules: `authenticated` cannot `UPDATE project_id` or `created_by` (column grants). A trigger also rejects those changes. Contributors may update title/description/status/position/assignee only on tasks they created or are assigned to.

## Deletion / retention

| Object | On delete |
| --- | --- |
| auth user | profile cascades; memberships cascade; tasks/comments/files keep author via `RESTRICT` or `SET NULL` where history matters |
| organisation | projects, memberships, invitations cascade |
| project | tasks, comments, project_files cascade |
| audit_events | `ON DELETE SET NULL` for org/project/actor so history survives |

Account deletion is not a silent cascade of authored work. Tasks remain with `created_by RESTRICT` until reassigned or anonymized in a dedicated admin operation (documented, not automatic).

## Storage

Private bucket `project-files`. Path: `{organisation_id}/{project_id}/{object_id}`.

Download: `can_view_project`. Upload: write content roles. Delete: `can_delete_project_file` (uploader, project manager, org owner, or org admin who can already view the project — so confidential admins without membership cannot delete). Cross-project rename is blocked by trigger.

MIME allow-list and 50 MiB limit are bucket configuration. Signed URLs, if used, should be created only after `can_view_project` and expire in minutes, not hours.

## Realtime

Broadcast on private topic `project:<project_id>`. Authorisation is `can_view_project`. Payloads contain ids, status, position, version — not description/body or other tenant columns.

Access revocation: a new subscribe is denied as soon as membership is removed. Existing JWT remains valid until expiry (`jwt_expiry = 3600`). Long-lived sockets should refresh the JWT; after refresh, Realtime re-evaluates policies. There is no global tenant-wide channel.

## Webhook failure semantics

`record_webhook_event` inserts first with a unique `(provider, event_id)`. Duplicate deliveries return `false` and create no second row. The Edge Function verifies HMAC against the **raw** body before any parse and before any RPC. Invalid signatures never call the database.

If insert succeeds and a later business step were added, that work must happen in the same transaction as the insert. The current business effect **is** the durable event row. That avoids marking processed without an effect.

## Future: immutable task revision history

Add `task_revisions` with `id`, `task_id`, `changed_at`, `actor_id`, `title`, `description`, `status`. Insert-only RLS. A `BEFORE UPDATE` trigger on `tasks` copies OLD into `task_revisions`. Revoke UPDATE/DELETE on revisions from all client roles. No user can rewrite prior rows.

## Trade-offs

- SECURITY DEFINER helpers are a concentrated privilege surface; they are locked down and tested instead of duplicating membership SQL in every policy.
- Broadcast over Postgres Changes avoids leaking extra columns through replica identity.
- Large comment volumes are indexed `(project_id, created_at DESC)` only; author-id index is omitted (see PERFORMANCE.md).

## Likely next refactors

- Partition `audit_events` and `comments` by time once those tables leave demo scale.
- Replace in-function HMAC-then-RPC with a single DB transaction that includes any future side effects besides the idempotency row.
- Add `task_revisions` as sketched above if product wants immutable history.
- Move `invite-member` email send behind a queue worker so the Edge Function only creates the digest row.
