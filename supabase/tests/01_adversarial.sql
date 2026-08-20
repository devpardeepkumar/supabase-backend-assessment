begin;
create schema if not exists tests;

create or replace function tests.set_claims(_id uuid, _email text)
returns void
language sql
as $$
  select
    set_config('request.jwt.claim.sub', _id::text, true),
    set_config('request.jwt.claim.role', 'authenticated', true),
    set_config('request.jwt.claim.email', _email, true),
    set_config(
      'request.jwt.claims',
      json_build_object('sub', _id::text, 'email', _email, 'role', 'authenticated')::text,
      true
    );
$$;

select plan(29);

-- 01 anonymous
set role anon;
select throws_ok(
  'select count(*) from public.organisations',
  '42501'
);
select throws_ok(
  'select count(*) from public.tasks',
  '42501'
);

-- 02 cross-tenant SELECT
reset role;
select tests.set_claims('a0000000-0000-0000-0000-000000000001', 'a-owner@example.com');
set role authenticated;
select is_empty(
  'select * from public.organisations where id = ''b0000000-0000-0000-0000-0000000000b1''',
  '02 org A owner cannot select org B'
);
select is_empty(
  'select * from public.tasks where id = ''b0000000-0000-0000-0000-000000000201''',
  '02 org A owner cannot select org B task by UUID'
);

-- 03 cross-tenant INSERT
select throws_ok(
  'insert into public.tasks (project_id, title, created_by) values (''b0000000-0000-0000-0000-000000000101'', ''evil'', auth.uid())',
  '42501'
);

-- 04 task reassignment
select throws_ok(
  'update public.tasks set project_id = ''b0000000-0000-0000-0000-000000000101'' where id = ''a0000000-0000-0000-0000-000000000201''',
  '42501'
);

-- 05 guest enumeration
reset role;
select tests.set_claims('a0000000-0000-0000-0000-000000000004', 'a-guest@example.com');
set role authenticated;
select is(
  (select count(*)::int from public.organisation_memberships
    where organisation_id = 'a0000000-0000-0000-0000-0000000000a1'),
  1,
  '05 guest can only see their own organisation membership'
);

-- 06 admin cannot attack owner
reset role;
select tests.set_claims('a0000000-0000-0000-0000-000000000002', 'a-admin@example.com');
set role authenticated;
select is_empty(
  'update public.organisation_memberships set role = ''member'' where organisation_id = ''a0000000-0000-0000-0000-0000000000a1'' and role = ''owner'' returning id',
  '06 admin cannot demote owner via ordinary update'
);
select is_empty(
  'delete from public.organisation_memberships where organisation_id = ''a0000000-0000-0000-0000-0000000000a1'' and role = ''owner'' returning id',
  '06 admin cannot delete owner membership'
);

-- 07 contributor isolation
reset role;
select tests.set_claims('a0000000-0000-0000-0000-000000000006', 'a-contributor@example.com');
set role authenticated;
select is_empty(
  'update public.tasks set title = ''hijacked'' where id = ''a0000000-0000-0000-0000-000000000202'' returning id',
  '07 contributor cannot update an unrelated task'
);

-- 08 viewer restrictions
reset role;
select tests.set_claims('a0000000-0000-0000-0000-000000000007', 'a-viewer@example.com');
set role authenticated;
select throws_ok(
  'insert into public.tasks (project_id, title, created_by) values (''a0000000-0000-0000-0000-000000000101'', ''nope'', auth.uid())',
  '42501'
);
select throws_ok(
  'insert into public.comments (project_id, task_id, author_id, body) values (''a0000000-0000-0000-0000-000000000101'', ''a0000000-0000-0000-0000-000000000201'', auth.uid(), ''nope'')',
  '42501'
);
select throws_ok(
  'insert into public.project_files (organisation_id, project_id, storage_path, uploaded_by) values (''a0000000-0000-0000-0000-0000000000a1'', ''a0000000-0000-0000-0000-000000000101'', ''a0000000-0000-0000-0000-0000000000a1/a0000000-0000-0000-0000-000000000101/x'', auth.uid())',
  '42501'
);

-- 09 invitation replay
reset role;
select tests.set_claims('c0000000-0000-0000-0000-000000000001', 'invitee@example.com');
set role authenticated;
select lives_ok(
  'select public.accept_invitation(''0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'')',
  '09 first acceptance succeeds'
);
select throws_ok(
  'select public.accept_invitation(''0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'')',
  'P0001'
);

-- 10 wrong recipient
reset role;
insert into public.invitations (organisation_id, email, intended_role, token_hash, invited_by, expires_at)
values (
  'a0000000-0000-0000-0000-0000000000a1',
  'other@example.com',
  'member',
  extensions.digest(convert_to('wrong-recipient-token-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', 'UTF8'), 'sha256'),
  'a0000000-0000-0000-0000-000000000001',
  now() + interval '1 day'
);
select tests.set_claims('a0000000-0000-0000-0000-000000000003', 'a-member@example.com');
set role authenticated;
select throws_ok(
  'select public.accept_invitation(''wrong-recipient-token-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'')',
  '42501'
);

-- 11 / 12 storage + realtime isolation share can_view_project
reset role;
select tests.set_claims('a0000000-0000-0000-0000-000000000006', 'a-contributor@example.com');
set role authenticated;
select is(
  public.can_view_project('b0000000-0000-0000-0000-000000000101'),
  false,
  '11/12 contributor cannot access other tenant project'
);
select is(
  public.can_view_project('a0000000-0000-0000-0000-000000000101'),
  true,
  '12 contributor can access their project'
);

-- 13 webhook duplication (service_role / postgres)
reset role;
select is(
  public.record_webhook_event('external', 'evt_1', 'ping', '{}'::jsonb),
  true,
  '13 first webhook delivery is processed'
);
select is(
  public.record_webhook_event('external', 'evt_1', 'ping', '{}'::jsonb),
  false,
  '13 duplicate webhook delivery is ignored'
);
select is(
  (select count(*)::int from public.webhook_events where event_id = 'evt_1'),
  1,
  '13 only one webhook row exists'
);

-- 15 stale version
select tests.set_claims('a0000000-0000-0000-0000-000000000006', 'a-contributor@example.com');
set role authenticated;
select lives_ok(
  'select public.transition_task(''a0000000-0000-0000-0000-000000000201'', 1, ''in_progress'')',
  '15 current version transition succeeds'
);
select throws_ok(
  'select public.transition_task(''a0000000-0000-0000-0000-000000000201'', 1, ''done'')',
  '40001'
);

-- extra: owner transfer, audit append-only, guest manager, fake owner
reset role;
select tests.set_claims('a0000000-0000-0000-0000-000000000002', 'a-admin@example.com');
set role authenticated;
select throws_ok(
  'select public.transfer_organisation_ownership(''a0000000-0000-0000-0000-0000000000a1'', ''a0000000-0000-0000-0000-000000000002'')',
  '42501'
);
select throws_ok(
  'update public.audit_events set action = ''tampered''',
  '42501'
);
select throws_ok(
  'delete from public.audit_events',
  '42501'
);
select throws_ok(
  'insert into public.audit_events (action, entity_type) values (''fake'', ''task'')',
  '42501'
);

reset role;
select tests.set_claims('a0000000-0000-0000-0000-000000000005', 'a-manager@example.com');
set role authenticated;
select throws_ok(
  'update public.project_memberships set role = ''manager'' where project_id = ''a0000000-0000-0000-0000-000000000101'' and user_id = ''a0000000-0000-0000-0000-000000000004''',
  'P0001'
);

reset role;
select tests.set_claims('a0000000-0000-0000-0000-000000000002', 'a-admin@example.com');
set role authenticated;
select throws_ok(
  'insert into public.organisation_memberships (organisation_id, user_id, role) values (''a0000000-0000-0000-0000-0000000000a1'', ''a0000000-0000-0000-0000-000000000003'', ''owner'')',
  '42501'
);

select * from finish();
rollback;
