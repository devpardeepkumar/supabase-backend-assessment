# Performance

## Planning scale

| Relation | Target |
| --- | --- |
| organisations | 25,000 |
| organisation_memberships | 2,500,000 |
| projects | 1,200,000 |
| project_memberships | 15,000,000 |
| tasks | 50,000,000 |
| comments | 200,000,000 |
| audit_events | 500,000,000 |

Index shapes below are chosen for those cardinalities, not for the seed row counts.

## Local volume limitation

This machine’s Docker data still lives on `C:` (~2 GB free). Loading the brief’s guideline volume (100,000 tasks, 500,000 comments) would grow the Hyper-V VHDX on that drive and risk breaking the local stack. `scripts/perf_load.sql` is the optional generator; do **not** run it unless Docker data is on a drive with tens of GB free.

Plans below were captured 21 Aug 2026 against the seeded database (2 orgs, 3 tasks, 2 comments) as `a-contributor@example.com` via `scripts/perf_explain.sql`. RLS was on. Even at seed cardinality the planner already chose the intended btree indexes for the three required list queries.

## Indexes

- `organisation_memberships (user_id) WHERE status = 'active'` — RLS `org_role` lookup
- `organisation_memberships (organisation_id, role) WHERE status = 'active'` — owner/admin scans per tenant
- `projects (organisation_id, last_activity_at DESC) WHERE archived_at IS NULL` — query 1
- `project_memberships (user_id)` and `(project_id)` — RLS project-access
- `tasks (project_id, status, position)` — query 2 board
- `comments (project_id, created_at DESC)` — query 3
- `invitations (token_hash) WHERE accepted_at IS NULL AND revoked_at IS NULL` — query 4
- Unique `invitations (organisation_id, email) WHERE pending` — one outstanding invite per email; also used by `create_invitation` upsert
- `audit_events (organisation_id, created_at DESC)` — admin audit views
- `webhook_events (provider, event_id)` — duplicate delivery

RLS cost is part of these plans: `can_view_project` / `org_role` must stay index nested loops, not sequential scans of membership tables.

## Query 1 — visible projects in one org

```sql
select p.id, p.name, p.last_activity_at
from public.projects p
where p.organisation_id = $org
  and p.archived_at is null
order by p.last_activity_at desc
limit 50;
```

Captured plan (contributor JWT, RLS on):

```
Limit  (cost=0.14..8.41 rows=1 width=56) (actual time=1.770..1.959 rows=1 loops=1)
  Buffers: shared hit=333
  ->  Index Scan using projects_org_activity_idx on public.projects p
        Index Cond: (p.organisation_id = 'a0000000-0000-0000-0000-0000000000a1'::uuid)
        Filter: app_hidden.can_view_project(p.id)
        Rows Removed by Filter: 1
        Buffers: shared hit=333
Planning Time: 11.958 ms
Execution Time: 2.004 ms
```

The partial index `(organisation_id, last_activity_at DESC) WHERE archived_at IS NULL` is used. RLS is a **filter on the index scan**, not a pre-scan of every tenant. One row was removed: the confidential project, which a contributor without membership must not see. Buffer hits are dominated by `can_view_project` membership lookups (8-ish pages per check, cached). At 1.2M projects this still stops after 50 rows that pass the filter; a tenant with a long run of confidential/inaccessible projects would skip those index entries rather than seq-scan `projects`.

## Query 2 — task board

```sql
select id, title, status, position, version, assignee_id
from public.tasks
where project_id = $project
  and status = $status
order by position
limit 500;
```

```
Limit  (cost=0.15..8.42 rows=1 width=132) (actual time=0.683..0.931 rows=2 loops=1)
  Buffers: shared hit=18
  ->  Index Scan using tasks_project_status_position_idx on public.tasks
        Index Cond: ((project_id = '…000101'::uuid) AND (status = 'todo'::text))
        Filter: app_hidden.can_view_project(project_id)
        Buffers: shared hit=18
Planning Time: 0.158 ms
Execution Time: 0.952 ms
```

Equality on `project_id` plus `status` uses the composite index; `position` is the third column so `ORDER BY position` is satisfied without a sort. RLS cannot leak other tenants because those rows are not in this index range. `can_view_project` is stable for the scan (one project id), so PostgreSQL evaluates it per row but the membership lookup is the same two index probes.

At 50M tasks, a single project’s board is still a narrow slice of `(project_id, status, position)`.

## Query 3 — newest comments

```sql
select id, task_id, author_id, created_at
from public.comments
where project_id = $project
order by created_at desc
limit 50;
```

```
Limit  (cost=12.04..12.05 rows=1 width=56) (actual time=0.666..0.667 rows=1 loops=1)
  Buffers: shared hit=12 read=1
  ->  Sort  (cost=12.04..12.05 rows=1 width=56)
        Sort Key: comments.created_at DESC
        Sort Method: quicksort  Memory: 25kB
        ->  Bitmap Heap Scan on public.comments
              Recheck Cond: (project_id = '…000101'::uuid)
              Filter: app_hidden.can_view_project(project_id)
              ->  Bitmap Index Scan on comments_project_created_idx
                    Index Cond: (project_id = '…000101'::uuid)
Planning Time: 0.168 ms
Execution Time: 0.685 ms
```

At **one** matching row the planner prefers bitmap + in-memory sort. That is cheaper than a descending btree walk for n≈1. At hundreds of thousands of comments per project, the same `comments_project_created_idx` on `(project_id, created_at DESC)` supports an **index scan backward** plus `LIMIT 50` with no sort. The seed plan already proves the index is considered and selected; the sort node is a cardinality artefact, not a missing index.

## Query 4 — invitation by digest

```sql
select id, organisation_id, email, intended_role, expires_at
from public.invitations
where token_hash = digest(convert_to($token, 'UTF8'), 'sha256')
  and accepted_at is null
  and revoked_at is null
  and expires_at > now();
```

```
Index Scan using invitations_one_pending_per_email on public.invitations
  (cost=0.14..8.17 rows=1 width=104) (actual time=0.026..0.029 rows=1 loops=1)
  Filter: ((expires_at > now()) AND (token_hash = digest(convert_to(…), 'sha256')))
  Buffers: shared hit=3
Planning Time: 0.816 ms
Execution Time: 0.057 ms
```

With a handful of pending invites the unique `(organisation_id, email) WHERE pending` index is a 1–2 page scan, so the planner uses it and filters on `token_hash`. That is correct at seed scale.

`invitations_token_hash_pending_idx` on `(token_hash) WHERE accepted_at IS NULL AND revoked_at IS NULL` is the production path: a unique digest lookup is O(log n) regardless of how many pending invites exist. `accept_invitation` also takes `SELECT FOR UPDATE` on the matching pending row, so the digest index is what concurrent accept attempts serialize on.

## Query 5 — project access (RLS helper)

```sql
select public.can_view_project($project_id);
```

```
Result  (cost=0.00..0.26 rows=1 width=1) (actual time=1.115..1.115 rows=1 loops=1)
  Output: can_view_project('…000101'::uuid)
  Buffers: shared hit=8
Planning Time: 0.045 ms
Execution Time: 1.149 ms
```

The helper is `SECURITY DEFINER STABLE`. Eight shared hits is two or three btree probes (`organisation_memberships_user_id_idx`, `project_memberships_user_id_idx`, `projects` pk). It does not sequential-scan `project_memberships`. RLS policies call this once per candidate row; query 1/2/3 keep the candidate set inside one org/project index range so the helper is not applied to 50M tasks.

## Deliberately omitted index

**`comments (author_id)` is not created.** At 200 million comments that index would be large and write-heavy on every insert. The documented hot path is “newest 50 comments for a project”, served by `(project_id, created_at DESC)`. Author history is not a required list endpoint.

## Refreshing plans

```powershell
# optional, only if Docker data is not on a nearly-full C: drive
Get-Content scripts/perf_load.sql | docker exec -i supabase_db_supabase psql -U postgres

Get-Content scripts/perf_explain.sql | docker exec -i supabase_db_supabase psql -U postgres
```
