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

select plan(5);

select tests.set_claims('a0000000-0000-0000-0000-000000000002', 'a-admin@example.com');
set role authenticated;
select is(
  public.can_view_project('a0000000-0000-0000-0000-000000000101'),
  true,
  'normal project: admin without membership is allowed'
);
select is(
  public.can_view_project('a0000000-0000-0000-0000-000000000102'),
  false,
  'confidential project: admin without membership is denied'
);

reset role;
select tests.set_claims('a0000000-0000-0000-0000-000000000001', 'a-owner@example.com');
set role authenticated;
select is(
  public.can_view_project('a0000000-0000-0000-0000-000000000102'),
  true,
  'confidential project: owner retains access'
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
select is(
  public.can_view_project('a0000000-0000-0000-0000-000000000102'),
  true,
  'confidential project: admin with explicit membership is allowed'
);
select isnt_empty(
  'select id from public.projects where id = ''a0000000-0000-0000-0000-000000000102''',
  'confidential project becomes visible to admin after explicit membership'
);

select * from finish();
rollback;
