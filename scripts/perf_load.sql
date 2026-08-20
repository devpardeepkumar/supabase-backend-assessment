-- Representative volume for EXPLAIN. Disable fan-out triggers so bulk load
-- does not invoke Realtime or rewrite last_activity_at per row.
-- Not part of seed.sql: evaluators with little disk can skip this file.

ALTER TABLE public.tasks DISABLE TRIGGER tasks_broadcast;
ALTER TABLE public.tasks DISABLE TRIGGER tasks_touch_project;
ALTER TABLE public.comments DISABLE TRIGGER comments_broadcast;
ALTER TABLE public.comments DISABLE TRIGGER comments_touch_project;

INSERT INTO public.tasks (project_id, title, created_by, status, position)
SELECT
  'a0000000-0000-0000-0000-000000000101'::uuid,
  'perf-' || i,
  'a0000000-0000-0000-0000-000000000006'::uuid,
  CASE WHEN i % 10 = 0 THEN 'in_progress' ELSE 'todo' END,
  i
FROM generate_series(1, 100000) AS i;

INSERT INTO public.comments (project_id, task_id, author_id, body, created_at)
SELECT
  'a0000000-0000-0000-0000-000000000101'::uuid,
  'a0000000-0000-0000-0000-000000000201'::uuid,
  'a0000000-0000-0000-0000-000000000006'::uuid,
  'perf comment ' || i,
  timestamptz '2026-01-01' + (i || ' milliseconds')::interval
FROM generate_series(1, 500000) AS i;

ALTER TABLE public.tasks ENABLE TRIGGER tasks_broadcast;
ALTER TABLE public.tasks ENABLE TRIGGER tasks_touch_project;
ALTER TABLE public.comments ENABLE TRIGGER comments_broadcast;
ALTER TABLE public.comments ENABLE TRIGGER comments_touch_project;

ANALYZE public.tasks;
ANALYZE public.comments;
ANALYZE public.projects;
ANALYZE public.organisation_memberships;
ANALYZE public.project_memberships;
ANALYZE public.invitations;

SELECT
  (SELECT count(*) FROM public.tasks) AS tasks,
  (SELECT count(*) FROM public.comments) AS comments;
