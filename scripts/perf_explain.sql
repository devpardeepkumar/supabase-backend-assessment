-- Capture hot-path plans as an authenticated project member (RLS on).
-- Intended for after scripts/perf_load.sql; still valid against seed volume.

SELECT set_config('request.jwt.claim.sub', 'a0000000-0000-0000-0000-000000000006', false);
SELECT set_config('request.jwt.claim.role', 'authenticated', false);
SELECT set_config('request.jwt.claim.email', 'a-contributor@example.com', false);
SELECT set_config(
  'request.jwt.claims',
  json_build_object(
    'sub', 'a0000000-0000-0000-0000-000000000006',
    'email', 'a-contributor@example.com',
    'role', 'authenticated'
  )::text,
  false
);
SET ROLE authenticated;

\echo === Q1 visible projects ===
EXPLAIN (ANALYZE, BUFFERS, VERBOSE)
SELECT p.id, p.name, p.last_activity_at
FROM public.projects p
WHERE p.organisation_id = 'a0000000-0000-0000-0000-0000000000a1'
  AND p.archived_at IS NULL
ORDER BY p.last_activity_at DESC
LIMIT 50;

\echo === Q2 task board ===
EXPLAIN (ANALYZE, BUFFERS, VERBOSE)
SELECT id, title, status, position, version, assignee_id
FROM public.tasks
WHERE project_id = 'a0000000-0000-0000-0000-000000000101'
  AND status = 'todo'
ORDER BY position
LIMIT 500;

\echo === Q3 newest comments ===
EXPLAIN (ANALYZE, BUFFERS, VERBOSE)
SELECT id, task_id, author_id, created_at
FROM public.comments
WHERE project_id = 'a0000000-0000-0000-0000-000000000101'
ORDER BY created_at DESC
LIMIT 50;

RESET ROLE;

\echo === Q4 invitation digest ===
EXPLAIN (ANALYZE, BUFFERS, VERBOSE)
SELECT id, organisation_id, email, intended_role, expires_at
FROM public.invitations
WHERE token_hash = extensions.digest(
    convert_to('0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef', 'UTF8'),
    'sha256'
  )
  AND accepted_at IS NULL
  AND revoked_at IS NULL
  AND expires_at > now();

SELECT set_config('request.jwt.claim.sub', 'a0000000-0000-0000-0000-000000000006', false);
SELECT set_config('request.jwt.claim.role', 'authenticated', false);
SELECT set_config(
  'request.jwt.claims',
  json_build_object(
    'sub', 'a0000000-0000-0000-0000-000000000006',
    'email', 'a-contributor@example.com',
    'role', 'authenticated'
  )::text,
  false
);
SET ROLE authenticated;

\echo === Q5 project access helper ===
EXPLAIN (ANALYZE, BUFFERS, VERBOSE)
SELECT public.can_view_project('a0000000-0000-0000-0000-000000000101');

RESET ROLE;
