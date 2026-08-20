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

select plan(18);

-- Anonymous denied on every sensitive tenant table (brief 13.1 / 01).
set role anon;
select throws_ok('select count(*) from public.organisations', '42501');
select throws_ok('select count(*) from public.organisation_memberships', '42501');
select throws_ok('select count(*) from public.projects', '42501');
select throws_ok('select count(*) from public.comments', '42501');
select throws_ok('select count(*) from public.invitations', '42501');
select throws_ok('select count(*) from public.audit_events', '42501');
select throws_ok('select count(*) from public.project_files', '42501');
select throws_ok('select count(*) from public.webhook_events', '42501');

-- Self-join: a member cannot insert themselves into another organisation.
reset role;
select tests.set_claims('a0000000-0000-0000-0000-000000000003', 'a-member@example.com');
set role authenticated;
select throws_ok(
  $$insert into public.organisation_memberships (organisation_id, user_id, role)
    values ('b0000000-0000-0000-0000-0000000000b1', auth.uid(), 'member')$$,
  '42501'
);

-- Member cannot create a project (owner/admin only).
select throws_ok(
  $$insert into public.projects (organisation_id, name, created_by)
    values ('a0000000-0000-0000-0000-0000000000a1', 'rogue', auth.uid())$$,
  '42501'
);

-- Member cannot archive/delete a project (row is not visible for those ops).
select is_empty(
  $$update public.projects set archived_at = now()
    where id = 'a0000000-0000-0000-0000-000000000101' returning id$$,
  'member cannot archive a project'
);
select is_empty(
  $$delete from public.projects where id = 'a0000000-0000-0000-0000-000000000101' returning id$$,
  'member cannot delete a project'
);

-- Profiles are not a global directory: guest cannot read a foreign-tenant profile.
reset role;
select tests.set_claims('a0000000-0000-0000-0000-000000000004', 'a-guest@example.com');
set role authenticated;
select is_empty(
  $$select id from public.profiles where id = 'b0000000-0000-0000-0000-000000000001'$$,
  'guest cannot read Organisation B profile'
);

-- Comment moderation: viewer cannot edit someone else's comment; author can edit own.
reset role;
select tests.set_claims('a0000000-0000-0000-0000-000000000007', 'a-viewer@example.com');
set role authenticated;
select is_empty(
  $$update public.comments set body = 'hijack'
    where id = 'a0000000-0000-0000-0000-000000000301' returning id$$,
  'viewer cannot edit another user comment'
);

reset role;
select tests.set_claims('a0000000-0000-0000-0000-000000000006', 'a-contributor@example.com');
set role authenticated;
select lives_ok(
  $$update public.comments set body = 'edited by author'
    where id = 'a0000000-0000-0000-0000-000000000301'$$,
  'comment author can edit their own comment'
);

-- Storage delete: foreign tenant cannot remove an Org A object by path.
reset role;
insert into storage.objects (bucket_id, name, owner, owner_id)
values (
  'project-files',
  'a0000000-0000-0000-0000-0000000000a1/a0000000-0000-0000-0000-000000000101/dddddddd-dddd-dddd-dddd-dddddddddddd',
  'a0000000-0000-0000-0000-000000000006',
  'a0000000-0000-0000-0000-000000000006'
);
-- Storage: foreign tenant cannot even see an Org A object, so they cannot delete it.
select tests.set_claims('b0000000-0000-0000-0000-000000000001', 'b-owner@example.com');
set role authenticated;
select is_empty(
  $$select id from storage.objects
    where name = 'a0000000-0000-0000-0000-0000000000a1/a0000000-0000-0000-0000-000000000101/dddddddd-dddd-dddd-dddd-dddddddddddd'$$,
  'foreign tenant cannot see Org A object to delete it'
);

-- Guest cannot see Organisation A projects they are not assigned to (confidential).
reset role;
select tests.set_claims('a0000000-0000-0000-0000-000000000004', 'a-guest@example.com');
set role authenticated;
select is_empty(
  $$select id from public.projects where id = 'a0000000-0000-0000-0000-000000000102'$$,
  'guest without membership cannot view confidential project'
);

-- Client-supplied role cannot escalate: member cannot promote self to owner.
reset role;
select tests.set_claims('a0000000-0000-0000-0000-000000000003', 'a-member@example.com');
set role authenticated;
select is_empty(
  $$update public.organisation_memberships set role = 'owner'
    where user_id = auth.uid() returning id$$,
  'member cannot self-promote to owner'
);

select * from finish();
rollback;
