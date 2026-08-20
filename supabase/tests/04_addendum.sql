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

select plan(23);

-- Expired invitation.
reset role;
insert into public.invitations (organisation_id, email, intended_role, token_hash, invited_by, expires_at)
values (
  'a0000000-0000-0000-0000-0000000000a1',
  'a-member@example.com',
  'member',
  extensions.digest(convert_to('expired-token-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'UTF8'), 'sha256'),
  'a0000000-0000-0000-0000-000000000001',
  now() - interval '1 hour'
);
select tests.set_claims('a0000000-0000-0000-0000-000000000003', 'a-member@example.com');
set role authenticated;
select throws_ok(
  $$select public.accept_invitation('expired-token-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')$$,
  'P0001'
);

-- Failed accept does not mark the invite accepted or write a success audit.
reset role;
insert into public.invitations (organisation_id, email, intended_role, token_hash, invited_by, expires_at)
values (
  'a0000000-0000-0000-0000-0000000000a1',
  'partial-audit@example.com',
  'member',
  extensions.digest(convert_to('partial-audit-token-bbbbbbbbbbbbbbbbbbbbbbbbbbbb', 'UTF8'), 'sha256'),
  'a0000000-0000-0000-0000-000000000001',
  now() + interval '1 day'
);
select tests.set_claims('a0000000-0000-0000-0000-000000000003', 'a-member@example.com');
set role authenticated;
select throws_ok(
  $$select public.accept_invitation('partial-audit-token-bbbbbbbbbbbbbbbbbbbbbbbbbbbb')$$,
  '42501'
);
reset role;
select is(
  (select accepted_at is null from public.invitations
    where email = 'partial-audit@example.com' and accepted_at is null),
  true,
  'failed accept leaves invitation pending'
);
select is(
  (select count(*)::int from public.audit_events
    where action = 'invitation_accepted'
      and (after_state->>'role') is not null
      and entity_id = (select id from public.invitations where email = 'partial-audit@example.com')),
  0,
  'failed accept writes no invitation_accepted audit row'
);

-- Privileges: webhook recorder is service_role only.
select is(
  has_function_privilege('authenticated', 'public.record_webhook_event(text,text,text,jsonb)', 'EXECUTE'),
  false,
  'authenticated cannot EXECUTE record_webhook_event'
);
select tests.set_claims('a0000000-0000-0000-0000-000000000001', 'a-owner@example.com');
set role authenticated;
select throws_ok(
  $$select public.record_webhook_event('external', 'evt_priv', 'ping', '{}'::jsonb)$$,
  '42501'
);

-- invite-member RPC authorisation: member and guest denied; owner allowed.
reset role;
select tests.set_claims('a0000000-0000-0000-0000-000000000003', 'a-member@example.com');
set role authenticated;
select throws_ok(
  $$select public.create_invitation(
      'a0000000-0000-0000-0000-0000000000a1',
      'member-forged@example.com',
      'member',
      'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      now() + interval '1 day'
    )$$,
  '42501'
);

reset role;
select tests.set_claims('a0000000-0000-0000-0000-000000000004', 'a-guest@example.com');
set role authenticated;
select throws_ok(
  $$select public.create_invitation(
      'a0000000-0000-0000-0000-0000000000a1',
      'guest-forged@example.com',
      'member',
      'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
      now() + interval '1 day'
    )$$,
  '42501'
);

reset role;
select tests.set_claims('a0000000-0000-0000-0000-000000000001', 'a-owner@example.com');
set role authenticated;
select lives_ok(
  $$select public.create_invitation(
      'a0000000-0000-0000-0000-0000000000a1',
      'addendum-invite@example.com',
      'member',
      'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
      now() + interval '1 day'
    )$$,
  'owner can create an invitation'
);

-- Confidential storage must be tested while 0002 is still an admin, not owner.
reset role;
insert into storage.objects (bucket_id, name, owner, owner_id)
values (
  'project-files',
  'a0000000-0000-0000-0000-0000000000a1/a0000000-0000-0000-0000-000000000102/cccccccc-cccc-cccc-cccc-cccccccccccc',
  'a0000000-0000-0000-0000-000000000001',
  'a0000000-0000-0000-0000-000000000001'
);

select tests.set_claims('a0000000-0000-0000-0000-000000000002', 'a-admin@example.com');
set role authenticated;
select is_empty(
  $$select id from storage.objects
    where name = 'a0000000-0000-0000-0000-0000000000a1/a0000000-0000-0000-0000-000000000102/cccccccc-cccc-cccc-cccc-cccccccccccc'$$,
  'confidential project: admin without membership cannot read storage'
);

reset role;
insert into public.project_memberships (project_id, user_id, role)
values (
  'a0000000-0000-0000-0000-000000000102',
  'a0000000-0000-0000-0000-000000000002',
  'viewer'
);
select tests.set_claims('a0000000-0000-0000-0000-000000000002', 'a-admin@example.com');
set role authenticated;
select isnt_empty(
  $$select id from storage.objects
    where name = 'a0000000-0000-0000-0000-0000000000a1/a0000000-0000-0000-0000-000000000102/cccccccc-cccc-cccc-cccc-cccccccccccc'$$,
  'confidential project: admin with membership can read storage'
);

reset role;
select tests.set_claims('a0000000-0000-0000-0000-000000000006', 'a-contributor@example.com');
set role authenticated;
select is(
  public.can_view_project('a0000000-0000-0000-0000-000000000102'),
  false,
  'confidential project: contributor without membership cannot subscribe'
);

-- Successful ownership transfer: previous owner becomes admin; audit row written.
reset role;
select tests.set_claims('a0000000-0000-0000-0000-000000000001', 'a-owner@example.com');
set role authenticated;
select lives_ok(
  $$select public.transfer_organisation_ownership(
      'a0000000-0000-0000-0000-0000000000a1',
      'a0000000-0000-0000-0000-000000000002'
    )$$,
  'owner can transfer ownership to an active admin'
);
reset role;
select is(
  (select role from public.organisation_memberships
    where organisation_id = 'a0000000-0000-0000-0000-0000000000a1'
      and user_id = 'a0000000-0000-0000-0000-000000000001'),
  'admin',
  'previous owner is now admin'
);
select is(
  (select role from public.organisation_memberships
    where organisation_id = 'a0000000-0000-0000-0000-0000000000a1'
      and user_id = 'a0000000-0000-0000-0000-000000000002'),
  'owner',
  'target member is now owner'
);
select isnt_empty(
  $$select id from public.audit_events
    where action = 'ownership_transferred'
      and organisation_id = 'a0000000-0000-0000-0000-0000000000a1'$$,
  'ownership transfer writes an audit event'
);

-- Cross-organisation project membership and project move.
select throws_ok(
  $$insert into public.project_memberships (project_id, user_id, role)
    values (
      'a0000000-0000-0000-0000-000000000101',
      'b0000000-0000-0000-0000-000000000001',
      'viewer'
    )$$,
  'P0001'
);
select throws_ok(
  $$update public.projects
      set organisation_id = 'b0000000-0000-0000-0000-0000000000b1'
    where id = 'a0000000-0000-0000-0000-000000000101'$$,
  'P0001'
);

-- Field-level: contributor cannot change created_by.
select tests.set_claims('a0000000-0000-0000-0000-000000000006', 'a-contributor@example.com');
set role authenticated;
select throws_ok(
  $$update public.tasks
      set created_by = 'a0000000-0000-0000-0000-000000000001'
    where id = 'a0000000-0000-0000-0000-000000000201'$$,
  '42501'
);

-- Task transition writes before/after audit (still version 1 in this transaction).
select lives_ok(
  $$select public.transition_task(
      'a0000000-0000-0000-0000-000000000201',
      1,
      'in_progress'
    )$$,
  'contributor can transition an assigned/created task'
);
reset role;
select isnt_empty(
  $$select id from public.audit_events
    where action = 'task_status_transition'
      and entity_id = 'a0000000-0000-0000-0000-000000000201'
      and before_state->>'status' = 'todo'
      and after_state->>'status' = 'in_progress'$$,
  'task transition records before/after audit state'
);

-- Invitation accept returns only authorised keys and writes audit.
select tests.set_claims('c0000000-0000-0000-0000-000000000001', 'invitee@example.com');
set role authenticated;
select is(
  (select array_agg(k order by k)
    from jsonb_object_keys(
      public.accept_invitation('0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef')
    ) as k),
  array['organisation_id', 'role']::text[],
  'accept_invitation returns only organisation_id and role'
);
reset role;
select isnt_empty(
  $$select id from public.audit_events where action = 'invitation_accepted'$$,
  'invitation accept writes an audit event'
);

select * from finish();
rollback;
