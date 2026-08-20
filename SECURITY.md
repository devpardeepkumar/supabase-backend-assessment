# Security

## Threat model

The client is hostile. An authenticated attacker knows table names, RPCs, UUIDs, storage paths, Realtime topics, and Edge Function URLs. They can mint arbitrary PostgREST filters and RPC arguments.

Goals:

- No cross-tenant read or write of private data through the anon/authenticated API
- No privilege escalation via client-supplied roles or user ids
- No invitation or webhook replay
- No service-role key in client code or git

## Trusted identity

Authoritative identity is `auth.uid()` and `auth.jwt()->>'email'`.

Not authoritative:

- `raw_user_meta_data`
- request body `user_id` / `organisation_id` / `role` / `is_admin` / `is_owner`
- Storage `owner` alone
- Channel name obscurity

## PostgreSQL privileges

`anon` has `USAGE` on `public` and no table DML on tenant tables.

`authenticated` receives explicit `GRANT`s. Task `project_id` and `created_by` are not updatable. Audit and webhook tables have no client write grants.

`app_hidden` is not in the Data API schema list. Functions in that schema have `EXECUTE` revoked from `PUBLIC`.

`service_role` bypasses RLS. It is used only in:

- local `seed.sql` (postgres role, not the JS client)
- `external-webhook` after HMAC verification, to call `record_webhook_event`

`invite-member` uses the **caller JWT** and `create_invitation`, not the service role.

## RLS

Every tenant table has RLS enabled and forced. `USING` and `WITH CHECK` are both defined for updates so a row cannot be moved into another tenant.

Membership policies do not subquery the same table under RLS.

## SECURITY DEFINER rules

Used only when invoker rights cannot read the required rows or must write audit/membership atomically. Each function:

1. Sets `search_path`
2. Qualifies objects
3. Checks `auth.uid()` (except webhook recorder, which is granted only to `service_role`)
4. Has restricted `EXECUTE`

## Invitations

- 256-bit random token
- Store SHA-256 digest only
- Bind to JWT email
- Expiry and accepted-at checks
- `SELECT FOR UPDATE` + unique pending `(organisation_id, email)`
- Response from `accept_invitation` returns organisation id and role only

## Webhooks

Signature payload is `timestamp + '.' + rawBody`. Verification happens before `JSON.parse`. Tolerance is 300 seconds. Duplicate `event_id` is a no-op.

## Storage and Realtime

Same `can_view_project` helper. Path `{org}/{project}/{object}`. Move across org/project raises. Deletes use `can_delete_project_file`. Realtime topic `project:<uuid>`; guessing a UUID does not grant access.

## Residual risks

- A stolen user JWT is valid until expiry (1 hour). Revocation of membership is immediate for new requests; open sockets need JWT refresh.
- `SECURITY DEFINER` bugs would be high impact; tests target those functions.
- Local demo keys are public by design and must never be used in production.
- MIME allow-lists still trust client metadata at the Storage API layer; treat uploaded files as untrusted content.
- Generating large performance datasets locally may be limited by disk. This checkout captured plans against seed data; see PERFORMANCE.md.
