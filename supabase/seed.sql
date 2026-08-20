--------------------------------------------------------------------------------
-- Seed fixtures for two organisations, every role, and adversarial cases.
-- Auth users are inserted as the migration role (postgres), NEVER as service_role.
-- Password for every seeded user: "password"
--------------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION app_hidden.seed_user(
  _id uuid,
  _email text,
  _full_name text
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, auth, public, extensions
AS $$
BEGIN
  INSERT INTO auth.users (
    instance_id, id, aud, role, email, encrypted_password, email_confirmed_at,
    raw_app_meta_data, raw_user_meta_data, created_at, updated_at,
    confirmation_token, email_change, email_change_token_new, recovery_token,
    is_sso_user, is_anonymous
  ) VALUES (
    '00000000-0000-0000-0000-000000000000',
    _id,
    'authenticated',
    'authenticated',
    lower(_email),
    crypt('password', gen_salt('bf')),
    now(),
    '{"provider":"email","providers":["email"]}'::jsonb,
    jsonb_build_object('full_name', _full_name),
    now(),
    now(),
    '',
    '',
    '',
    '',
    false,
    false
  )
  ON CONFLICT (id) DO NOTHING;

  INSERT INTO auth.identities (
    id, user_id, identity_data, provider, provider_id, last_sign_in_at, created_at, updated_at
  ) VALUES (
    gen_random_uuid(),
    _id,
    jsonb_build_object('sub', _id::text, 'email', lower(_email)),
    'email',
    _id::text,
    now(),
    now(),
    now()
  )
  ON CONFLICT (provider_id, provider) DO NOTHING;
END;
$$;

SELECT app_hidden.seed_user('a0000000-0000-0000-0000-000000000001', 'a-owner@example.com', 'Org A Owner');
SELECT app_hidden.seed_user('a0000000-0000-0000-0000-000000000002', 'a-admin@example.com', 'Org A Admin');
SELECT app_hidden.seed_user('a0000000-0000-0000-0000-000000000003', 'a-member@example.com', 'Org A Member');
SELECT app_hidden.seed_user('a0000000-0000-0000-0000-000000000004', 'a-guest@example.com', 'Org A Guest');
SELECT app_hidden.seed_user('a0000000-0000-0000-0000-000000000005', 'a-manager@example.com', 'Org A Manager');
SELECT app_hidden.seed_user('a0000000-0000-0000-0000-000000000006', 'a-contributor@example.com', 'Org A Contributor');
SELECT app_hidden.seed_user('a0000000-0000-0000-0000-000000000007', 'a-viewer@example.com', 'Org A Viewer');
SELECT app_hidden.seed_user('a0000000-0000-0000-0000-000000000008', 'a-contributor-2@example.com', 'Org A Contributor 2');
SELECT app_hidden.seed_user('b0000000-0000-0000-0000-000000000001', 'b-owner@example.com', 'Org B Owner');
SELECT app_hidden.seed_user('b0000000-0000-0000-0000-000000000002', 'b-admin@example.com', 'Org B Admin');
SELECT app_hidden.seed_user('c0000000-0000-0000-0000-000000000001', 'invitee@example.com', 'Invitee');

INSERT INTO public.organisations (id, name, status)
VALUES
  ('a0000000-0000-0000-0000-0000000000a1', 'Organization A', 'active'),
  ('b0000000-0000-0000-0000-0000000000b1', 'Organization B', 'active')
ON CONFLICT (id) DO NOTHING;

INSERT INTO public.organisation_memberships (organisation_id, user_id, role, status)
VALUES
  ('a0000000-0000-0000-0000-0000000000a1', 'a0000000-0000-0000-0000-000000000001', 'owner', 'active'),
  ('a0000000-0000-0000-0000-0000000000a1', 'a0000000-0000-0000-0000-000000000002', 'admin', 'active'),
  ('a0000000-0000-0000-0000-0000000000a1', 'a0000000-0000-0000-0000-000000000003', 'member', 'active'),
  ('a0000000-0000-0000-0000-0000000000a1', 'a0000000-0000-0000-0000-000000000004', 'guest', 'active'),
  ('a0000000-0000-0000-0000-0000000000a1', 'a0000000-0000-0000-0000-000000000005', 'member', 'active'),
  ('a0000000-0000-0000-0000-0000000000a1', 'a0000000-0000-0000-0000-000000000006', 'member', 'active'),
  ('a0000000-0000-0000-0000-0000000000a1', 'a0000000-0000-0000-0000-000000000007', 'member', 'active'),
  ('a0000000-0000-0000-0000-0000000000a1', 'a0000000-0000-0000-0000-000000000008', 'member', 'active'),
  ('b0000000-0000-0000-0000-0000000000b1', 'b0000000-0000-0000-0000-000000000001', 'owner', 'active'),
  ('b0000000-0000-0000-0000-0000000000b1', 'b0000000-0000-0000-0000-000000000002', 'admin', 'active')
ON CONFLICT (organisation_id, user_id) DO NOTHING;

INSERT INTO public.projects (id, organisation_id, name, status, access_mode, created_by)
VALUES
  ('a0000000-0000-0000-0000-000000000101', 'a0000000-0000-0000-0000-0000000000a1', 'Org A Normal Project', 'active', 'normal', 'a0000000-0000-0000-0000-000000000001'),
  ('a0000000-0000-0000-0000-000000000102', 'a0000000-0000-0000-0000-0000000000a1', 'Org A Confidential Project', 'active', 'confidential', 'a0000000-0000-0000-0000-000000000001'),
  ('b0000000-0000-0000-0000-000000000101', 'b0000000-0000-0000-0000-0000000000b1', 'Org B Project', 'active', 'normal', 'b0000000-0000-0000-0000-000000000001')
ON CONFLICT (id) DO NOTHING;

INSERT INTO public.project_memberships (project_id, user_id, role)
VALUES
  ('a0000000-0000-0000-0000-000000000101', 'a0000000-0000-0000-0000-000000000005', 'manager'),
  ('a0000000-0000-0000-0000-000000000101', 'a0000000-0000-0000-0000-000000000006', 'contributor'),
  ('a0000000-0000-0000-0000-000000000101', 'a0000000-0000-0000-0000-000000000007', 'viewer'),
  ('a0000000-0000-0000-0000-000000000101', 'a0000000-0000-0000-0000-000000000008', 'contributor'),
  ('a0000000-0000-0000-0000-000000000101', 'a0000000-0000-0000-0000-000000000004', 'viewer'),
  ('a0000000-0000-0000-0000-000000000102', 'a0000000-0000-0000-0000-000000000005', 'manager')
ON CONFLICT (project_id, user_id) DO NOTHING;

INSERT INTO public.tasks (id, project_id, title, description, status, position, version, created_by, assignee_id)
VALUES
  ('a0000000-0000-0000-0000-000000000201', 'a0000000-0000-0000-0000-000000000101', 'Contributor task', 'owned by contributor', 'todo', 1, 1, 'a0000000-0000-0000-0000-000000000006', 'a0000000-0000-0000-0000-000000000006'),
  ('a0000000-0000-0000-0000-000000000202', 'a0000000-0000-0000-0000-000000000101', 'Unrelated task', 'owned by manager', 'todo', 2, 1, 'a0000000-0000-0000-0000-000000000005', 'a0000000-0000-0000-0000-000000000005'),
  ('b0000000-0000-0000-0000-000000000201', 'b0000000-0000-0000-0000-000000000101', 'Org B task', 'other tenant', 'todo', 1, 1, 'b0000000-0000-0000-0000-000000000001', NULL)
ON CONFLICT (id) DO NOTHING;

INSERT INTO public.comments (id, project_id, task_id, author_id, body)
VALUES
  ('a0000000-0000-0000-0000-000000000301', 'a0000000-0000-0000-0000-000000000101', 'a0000000-0000-0000-0000-000000000201', 'a0000000-0000-0000-0000-000000000006', 'Hello from Org A'),
  ('b0000000-0000-0000-0000-000000000301', 'b0000000-0000-0000-0000-000000000101', 'b0000000-0000-0000-0000-000000000201', 'b0000000-0000-0000-0000-000000000001', 'Hello from Org B')
ON CONFLICT (id) DO NOTHING;

-- Pending invitation for invitee@example.com. Raw token used in tests:
-- 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
INSERT INTO public.invitations (
  id, organisation_id, email, intended_role, token_hash, invited_by, expires_at
) VALUES (
  'a0000000-0000-0000-0000-000000000401',
  'a0000000-0000-0000-0000-0000000000a1',
  'invitee@example.com',
  'member',
  digest('0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef', 'sha256'),
  'a0000000-0000-0000-0000-000000000001',
  now() + interval '7 days'
)
ON CONFLICT (id) DO NOTHING;
