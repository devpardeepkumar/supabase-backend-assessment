-- Core multi-tenant domain for Nexus Workspaces.
-- Roles use TEXT + CHECK (not ENUM) so future values can be added without a rewrite.

CREATE SCHEMA IF NOT EXISTS app_hidden;
REVOKE ALL ON SCHEMA app_hidden FROM PUBLIC;
REVOKE ALL ON SCHEMA app_hidden FROM anon, authenticated;

-- ---------------------------------------------------------------------------
-- Harden profile trigger from the previous migration
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.create_profile_for_new_user()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
  INSERT INTO public.profiles (id, full_name, avatar_url)
  VALUES (
    NEW.id,
    NEW.raw_user_meta_data->>'full_name',
    NEW.raw_user_meta_data->>'avatar_url'
  )
  ON CONFLICT (id) DO NOTHING;
  RETURN NEW;
END;
$$;

REVOKE ALL ON FUNCTION public.create_profile_for_new_user() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.create_profile_for_new_user() FROM anon, authenticated;

ALTER TABLE public.profiles
  ADD COLUMN IF NOT EXISTS created_at timestamptz NOT NULL DEFAULT now();

ALTER TABLE public.organisations
  ADD COLUMN IF NOT EXISTS updated_at timestamptz NOT NULL DEFAULT now();

DROP POLICY IF EXISTS "Organisation owners can manage their organisation." ON public.organisations;

-- Ownership lives on organisation_memberships (one active owner).

ALTER TABLE public.organisations
  DROP CONSTRAINT IF EXISTS organisations_status_check;

ALTER TABLE public.organisations
  ADD CONSTRAINT organisations_status_check
  CHECK (status IN ('active', 'inactive', 'suspended'));

-- Ownership lives on organisation_memberships (one active owner).
ALTER TABLE public.organisations
  DROP CONSTRAINT IF EXISTS organisations_owner_id_fkey;

ALTER TABLE public.organisations
  DROP COLUMN IF EXISTS owner_id;

CREATE TABLE public.organisation_memberships (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organisation_id uuid NOT NULL REFERENCES public.organisations (id) ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES public.profiles (id) ON DELETE CASCADE,
  role text NOT NULL,
  status text NOT NULL DEFAULT 'active',
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT organisation_memberships_role_check
    CHECK (role IN ('owner', 'admin', 'member', 'guest')),
  CONSTRAINT organisation_memberships_status_check
    CHECK (status IN ('active', 'invited', 'removed')),
  CONSTRAINT organisation_memberships_unique_user UNIQUE (organisation_id, user_id)
);

CREATE UNIQUE INDEX organisation_memberships_one_owner
  ON public.organisation_memberships (organisation_id)
  WHERE role = 'owner' AND status = 'active';

CREATE TABLE public.projects (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organisation_id uuid NOT NULL REFERENCES public.organisations (id) ON DELETE CASCADE,
  name text NOT NULL,
  description text,
  status text NOT NULL DEFAULT 'active',
  last_activity_at timestamptz NOT NULL DEFAULT now(),
  created_by uuid REFERENCES public.profiles (id) ON DELETE SET NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  archived_at timestamptz,
  CONSTRAINT projects_status_check CHECK (status IN ('active', 'archived')),
  CONSTRAINT projects_name_not_blank CHECK (length(btrim(name)) > 0)
);

CREATE TABLE public.project_memberships (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  project_id uuid NOT NULL REFERENCES public.projects (id) ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES public.profiles (id) ON DELETE CASCADE,
  role text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT project_memberships_role_check
    CHECK (role IN ('manager', 'contributor', 'viewer')),
  CONSTRAINT project_memberships_unique_user UNIQUE (project_id, user_id)
);

CREATE TABLE public.tasks (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  project_id uuid NOT NULL REFERENCES public.projects (id) ON DELETE CASCADE,
  title text NOT NULL,
  description text,
  status text NOT NULL DEFAULT 'todo',
  position numeric NOT NULL DEFAULT 0,
  version integer NOT NULL DEFAULT 1,
  created_by uuid NOT NULL REFERENCES public.profiles (id) ON DELETE RESTRICT,
  assignee_id uuid REFERENCES public.profiles (id) ON DELETE SET NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT tasks_title_not_blank CHECK (length(btrim(title)) > 0),
  CONSTRAINT tasks_status_check CHECK (status IN ('todo', 'in_progress', 'done', 'blocked')),
  CONSTRAINT tasks_version_positive CHECK (version > 0)
);

CREATE TABLE public.comments (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  project_id uuid NOT NULL REFERENCES public.projects (id) ON DELETE CASCADE,
  task_id uuid REFERENCES public.tasks (id) ON DELETE CASCADE,
  author_id uuid NOT NULL REFERENCES public.profiles (id) ON DELETE RESTRICT,
  body text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT comments_body_not_blank CHECK (length(btrim(body)) > 0)
);

CREATE TABLE public.invitations (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organisation_id uuid NOT NULL REFERENCES public.organisations (id) ON DELETE CASCADE,
  email text NOT NULL,
  intended_role text NOT NULL,
  token_hash bytea NOT NULL,
  invited_by uuid NOT NULL REFERENCES public.profiles (id) ON DELETE RESTRICT,
  expires_at timestamptz NOT NULL,
  accepted_at timestamptz,
  accepted_by uuid REFERENCES public.profiles (id) ON DELETE SET NULL,
  revoked_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT invitations_role_check
    CHECK (intended_role IN ('admin', 'member', 'guest')),
  CONSTRAINT invitations_email_format CHECK (email = lower(email)),
  CONSTRAINT invitations_token_hash_unique UNIQUE (token_hash)
);

CREATE UNIQUE INDEX invitations_one_pending_per_email
  ON public.invitations (organisation_id, email)
  WHERE accepted_at IS NULL AND revoked_at IS NULL;

CREATE TABLE public.audit_events (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  organisation_id uuid REFERENCES public.organisations (id) ON DELETE SET NULL,
  project_id uuid REFERENCES public.projects (id) ON DELETE SET NULL,
  actor_id uuid REFERENCES public.profiles (id) ON DELETE SET NULL,
  action text NOT NULL,
  entity_type text NOT NULL,
  entity_id uuid,
  before_state jsonb,
  after_state jsonb,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE public.webhook_events (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  provider text NOT NULL DEFAULT 'external',
  event_id text NOT NULL,
  event_type text,
  payload jsonb,
  status text NOT NULL DEFAULT 'processed',
  processed_at timestamptz NOT NULL DEFAULT now(),
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT webhook_events_status_check
    CHECK (status IN ('processed', 'failed', 'ignored')),
  CONSTRAINT webhook_events_unique_event UNIQUE (provider, event_id)
);

CREATE TABLE public.project_files (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organisation_id uuid NOT NULL REFERENCES public.organisations (id) ON DELETE CASCADE,
  project_id uuid NOT NULL REFERENCES public.projects (id) ON DELETE CASCADE,
  storage_path text NOT NULL,
  original_name text,
  mime_type text,
  size_bytes bigint,
  uploaded_by uuid NOT NULL REFERENCES public.profiles (id) ON DELETE RESTRICT,
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT project_files_path_unique UNIQUE (storage_path),
  CONSTRAINT project_files_size_positive CHECK (size_bytes IS NULL OR size_bytes >= 0)
);

-- Cross-org integrity: project member must belong to the project's organisation.
CREATE OR REPLACE FUNCTION app_hidden.enforce_project_membership()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  v_org uuid;
  v_org_role text;
BEGIN
  SELECT p.organisation_id INTO v_org
  FROM public.projects p
  WHERE p.id = NEW.project_id;

  IF v_org IS NULL THEN
    RAISE EXCEPTION 'project does not exist';
  END IF;

  SELECT m.role INTO v_org_role
  FROM public.organisation_memberships m
  WHERE m.organisation_id = v_org
    AND m.user_id = NEW.user_id
    AND m.status = 'active';

  IF v_org_role IS NULL THEN
    RAISE EXCEPTION 'project member must belong to the same organisation as the project';
  END IF;

  IF v_org_role = 'guest' AND NEW.role = 'manager' THEN
    RAISE EXCEPTION 'guest cannot be promoted to project manager';
  END IF;

  RETURN NEW;
END;
$$;

CREATE TRIGGER project_memberships_integrity
  BEFORE INSERT OR UPDATE OF project_id, user_id, role
  ON public.project_memberships
  FOR EACH ROW
  EXECUTE FUNCTION app_hidden.enforce_project_membership();

CREATE OR REPLACE FUNCTION app_hidden.prevent_project_org_move()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
  IF TG_OP = 'UPDATE' AND NEW.organisation_id IS DISTINCT FROM OLD.organisation_id THEN
    RAISE EXCEPTION 'projects cannot be moved across organisations';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER projects_no_org_move
  BEFORE UPDATE ON public.projects
  FOR EACH ROW
  EXECUTE FUNCTION app_hidden.prevent_project_org_move();

CREATE OR REPLACE FUNCTION app_hidden.touch_updated_at()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
  NEW.updated_at = now();
  RETURN NEW;
END;
$$;

CREATE TRIGGER organisations_updated_at
  BEFORE UPDATE ON public.organisations
  FOR EACH ROW EXECUTE FUNCTION app_hidden.touch_updated_at();

CREATE TRIGGER organisation_memberships_updated_at
  BEFORE UPDATE ON public.organisation_memberships
  FOR EACH ROW EXECUTE FUNCTION app_hidden.touch_updated_at();

CREATE TRIGGER projects_updated_at
  BEFORE UPDATE ON public.projects
  FOR EACH ROW EXECUTE FUNCTION app_hidden.touch_updated_at();

CREATE TRIGGER project_memberships_updated_at
  BEFORE UPDATE ON public.project_memberships
  FOR EACH ROW EXECUTE FUNCTION app_hidden.touch_updated_at();

CREATE TRIGGER tasks_updated_at
  BEFORE UPDATE ON public.tasks
  FOR EACH ROW EXECUTE FUNCTION app_hidden.touch_updated_at();

CREATE TRIGGER comments_updated_at
  BEFORE UPDATE ON public.comments
  FOR EACH ROW EXECUTE FUNCTION app_hidden.touch_updated_at();
