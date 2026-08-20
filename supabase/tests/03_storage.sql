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

select plan(8);

-- Viewer cannot upload into a project they can only view.
reset role;
select tests.set_claims('a0000000-0000-0000-0000-000000000007', 'a-viewer@example.com');
set role authenticated;
select throws_ok(
  $$insert into storage.objects (bucket_id, name, owner, owner_id)
    values (
      'project-files',
      'a0000000-0000-0000-0000-0000000000a1/a0000000-0000-0000-0000-000000000101/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaa1',
      auth.uid(),
      auth.uid()::text
    )$$,
  '42501'
);

-- Contributor can upload into their project path.
reset role;
select tests.set_claims('a0000000-0000-0000-0000-000000000006', 'a-contributor@example.com');
set role authenticated;
select lives_ok(
  $$insert into storage.objects (bucket_id, name, owner, owner_id)
    values (
      'project-files',
      'a0000000-0000-0000-0000-0000000000a1/a0000000-0000-0000-0000-000000000101/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaa2',
      auth.uid(),
      auth.uid()::text
    )$$,
  'contributor can upload into own project path'
);

-- Path org/project mismatch (org A + project B) is rejected.
select throws_ok(
  $$insert into storage.objects (bucket_id, name, owner, owner_id)
    values (
      'project-files',
      'a0000000-0000-0000-0000-0000000000a1/b0000000-0000-0000-0000-000000000101/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaa3',
      auth.uid(),
      auth.uid()::text
    )$$,
  '42501'
);

-- Cross-tenant upload into Organisation B is rejected.
select throws_ok(
  $$insert into storage.objects (bucket_id, name, owner, owner_id)
    values (
      'project-files',
      'b0000000-0000-0000-0000-0000000000b1/b0000000-0000-0000-0000-000000000101/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaa4',
      auth.uid(),
      auth.uid()::text
    )$$,
  '42501'
);

-- Seed an object in org B as postgres, then prove contributor cannot read or move it.
reset role;
insert into storage.objects (bucket_id, name, owner, owner_id)
values (
  'project-files',
  'b0000000-0000-0000-0000-0000000000b1/b0000000-0000-0000-0000-000000000101/bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbb1',
  'b0000000-0000-0000-0000-000000000001',
  'b0000000-0000-0000-0000-000000000001'
);

select tests.set_claims('a0000000-0000-0000-0000-000000000006', 'a-contributor@example.com');
set role authenticated;
select is_empty(
  $$select id from storage.objects
    where name = 'b0000000-0000-0000-0000-0000000000b1/b0000000-0000-0000-0000-000000000101/bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbb1'$$,
  'contributor cannot download another tenant object by path'
);

select throws_ok(
  $$update storage.objects
      set name = 'b0000000-0000-0000-0000-0000000000b1/b0000000-0000-0000-0000-000000000101/stolen'
    where name = 'a0000000-0000-0000-0000-0000000000a1/a0000000-0000-0000-0000-000000000101/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaa2'$$,
  'P0001'
);

-- Org B owner cannot delete Org A object by guessing the path.
reset role;
select tests.set_claims('b0000000-0000-0000-0000-000000000001', 'b-owner@example.com');
set role authenticated;
select is(
  (select count(*)::int from storage.objects
    where name = 'a0000000-0000-0000-0000-0000000000a1/a0000000-0000-0000-0000-000000000101/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaa2'),
  0,
  'foreign tenant cannot see org A storage objects'
);

-- Realtime helper rejects a guessed project the caller cannot view.
reset role;
select tests.set_claims('a0000000-0000-0000-0000-000000000006', 'a-contributor@example.com');
set role authenticated;
select is(
  public.can_view_project('b0000000-0000-0000-0000-000000000101'),
  false,
  'realtime subscribe to a guessed foreign project id is denied by the same helper'
);

select * from finish();
rollback;
