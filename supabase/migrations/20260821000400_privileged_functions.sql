-- Privileged state changes. SECURITY DEFINER only where elevation is required.
-- Callers are still authorized inside the function using auth.uid().

CREATE OR REPLACE FUNCTION app_hidden.write_audit(
  _organisation_id uuid,
  _project_id uuid,
  _action text,
  _entity_type text,
  _entity_id uuid,
  _before jsonb DEFAULT NULL,
  _after jsonb DEFAULT NULL,
  _metadata jsonb DEFAULT '{}'::jsonb
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
  INSERT INTO public.audit_events (
    organisation_id, project_id, actor_id, action, entity_type, entity_id,
    before_state, after_state, metadata
  ) VALUES (
    _organisation_id, _project_id, auth.uid(), _action, _entity_type, _entity_id,
    _before, _after, COALESCE(_metadata, '{}'::jsonb)
  );
END;
$$;

REVOKE ALL ON FUNCTION app_hidden.write_audit(uuid, uuid, text, text, uuid, jsonb, jsonb, jsonb) FROM PUBLIC;

CREATE OR REPLACE FUNCTION app_hidden.prevent_task_project_move()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
  IF NEW.project_id IS DISTINCT FROM OLD.project_id THEN
    RAISE EXCEPTION 'tasks cannot be moved to another project';
  END IF;
  IF NEW.created_by IS DISTINCT FROM OLD.created_by THEN
    RAISE EXCEPTION 'task creator is immutable';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER tasks_freeze_identity
  BEFORE UPDATE ON public.tasks
  FOR EACH ROW
  EXECUTE FUNCTION app_hidden.prevent_task_project_move();

CREATE OR REPLACE FUNCTION app_hidden.touch_project_activity()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  v_project uuid;
BEGIN
  v_project := COALESCE(NEW.project_id, OLD.project_id);
  UPDATE public.projects
  SET last_activity_at = now()
  WHERE id = v_project;
  RETURN COALESCE(NEW, OLD);
END;
$$;

CREATE TRIGGER tasks_touch_project
  AFTER INSERT OR UPDATE OR DELETE ON public.tasks
  FOR EACH ROW
  EXECUTE FUNCTION app_hidden.touch_project_activity();

CREATE TRIGGER comments_touch_project
  AFTER INSERT OR UPDATE OR DELETE ON public.comments
  FOR EACH ROW
  EXECUTE FUNCTION app_hidden.touch_project_activity();

-- Ownership transfer: only current owner, atomic, locked, audited.
CREATE OR REPLACE FUNCTION public.transfer_organisation_ownership(
  _organisation_id uuid,
  _new_owner_id uuid
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  v_current_owner uuid;
  v_new_role text;
BEGIN
  IF auth.uid() IS NULL THEN
    RAISE EXCEPTION 'not authenticated' USING ERRCODE = '42501';
  END IF;

  PERFORM pg_advisory_xact_lock(hashtextextended(_organisation_id::text, 0));

  SELECT user_id INTO v_current_owner
  FROM public.organisation_memberships
  WHERE organisation_id = _organisation_id
    AND role = 'owner'
    AND status = 'active'
  FOR UPDATE;

  IF v_current_owner IS NULL OR v_current_owner <> auth.uid() THEN
    RAISE EXCEPTION 'only the current owner can transfer ownership' USING ERRCODE = '42501';
  END IF;

  IF _new_owner_id = v_current_owner THEN
    RAISE EXCEPTION 'new owner must be a different member';
  END IF;

  SELECT role INTO v_new_role
  FROM public.organisation_memberships
  WHERE organisation_id = _organisation_id
    AND user_id = _new_owner_id
    AND status = 'active'
  FOR UPDATE;

  IF v_new_role IS NULL THEN
    RAISE EXCEPTION 'new owner must be an active organisation member';
  END IF;

  UPDATE public.organisation_memberships
  SET role = 'admin'
  WHERE organisation_id = _organisation_id
    AND user_id = v_current_owner;

  UPDATE public.organisation_memberships
  SET role = 'owner'
  WHERE organisation_id = _organisation_id
    AND user_id = _new_owner_id;

  PERFORM app_hidden.write_audit(
    _organisation_id, NULL, 'ownership_transferred', 'organisation', _organisation_id,
    jsonb_build_object('owner_id', v_current_owner),
    jsonb_build_object('owner_id', _new_owner_id),
    '{}'::jsonb
  );

  RETURN jsonb_build_object(
    'organisation_id', _organisation_id,
    'previous_owner_id', v_current_owner,
    'previous_owner_new_role', 'admin',
    'new_owner_id', _new_owner_id
  );
END;
$$;

REVOKE ALL ON FUNCTION public.transfer_organisation_ownership(uuid, uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.transfer_organisation_ownership(uuid, uuid) TO authenticated;

-- Invitation accept: hash comparison, recipient bind, one-time, concurrent-safe.
CREATE OR REPLACE FUNCTION public.accept_invitation(_token text)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, extensions
AS $$
DECLARE
  v_hash bytea;
  v_inv public.invitations%ROWTYPE;
  v_email text;
BEGIN
  IF auth.uid() IS NULL THEN
    RAISE EXCEPTION 'not authenticated' USING ERRCODE = '42501';
  END IF;

  IF _token IS NULL OR length(_token) < 32 THEN
    RAISE EXCEPTION 'invalid invitation token' USING ERRCODE = '22023';
  END IF;

  v_hash := extensions.digest(convert_to(_token, 'UTF8'), 'sha256');
  v_email := app_hidden.jwt_email();

  SELECT * INTO v_inv
  FROM public.invitations
  WHERE token_hash = v_hash
  FOR UPDATE;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'invitation not found' USING ERRCODE = 'P0002';
  END IF;

  IF v_inv.revoked_at IS NOT NULL THEN
    RAISE EXCEPTION 'invitation revoked' USING ERRCODE = 'P0001';
  END IF;

  IF v_inv.accepted_at IS NOT NULL THEN
    RAISE EXCEPTION 'invitation already accepted' USING ERRCODE = 'P0001';
  END IF;

  IF v_inv.expires_at <= now() THEN
    RAISE EXCEPTION 'invitation expired' USING ERRCODE = 'P0001';
  END IF;

  IF v_email IS NULL OR v_email <> v_inv.email THEN
    RAISE EXCEPTION 'invitation is bound to a different account' USING ERRCODE = '42501';
  END IF;

  INSERT INTO public.organisation_memberships (organisation_id, user_id, role, status)
  VALUES (v_inv.organisation_id, auth.uid(), v_inv.intended_role, 'active')
  ON CONFLICT (organisation_id, user_id)
  DO UPDATE SET
    role = EXCLUDED.role,
    status = 'active',
    updated_at = now();

  UPDATE public.invitations
  SET accepted_at = now(),
      accepted_by = auth.uid()
  WHERE id = v_inv.id;

  PERFORM app_hidden.write_audit(
    v_inv.organisation_id, NULL, 'invitation_accepted', 'invitation', v_inv.id,
    jsonb_build_object('status', 'pending'),
    jsonb_build_object('status', 'accepted', 'role', v_inv.intended_role),
    jsonb_build_object('email', v_inv.email)
  );

  RETURN jsonb_build_object(
    'organisation_id', v_inv.organisation_id,
    'role', v_inv.intended_role
  );
END;
$$;

REVOKE ALL ON FUNCTION public.accept_invitation(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.accept_invitation(text) TO authenticated;

CREATE OR REPLACE FUNCTION public.transition_task(
  _task_id uuid,
  _expected_version integer,
  _new_status text
)
RETURNS public.tasks
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  v_task public.tasks%ROWTYPE;
  v_updated public.tasks%ROWTYPE;
BEGIN
  IF auth.uid() IS NULL THEN
    RAISE EXCEPTION 'not authenticated' USING ERRCODE = '42501';
  END IF;

  IF _new_status NOT IN ('todo', 'in_progress', 'done', 'blocked') THEN
    RAISE EXCEPTION 'invalid status' USING ERRCODE = '22023';
  END IF;

  SELECT * INTO v_task
  FROM public.tasks
  WHERE id = _task_id
  FOR UPDATE;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'task not found' USING ERRCODE = 'P0002';
  END IF;

  IF NOT app_hidden.can_update_task(_task_id) THEN
    RAISE EXCEPTION 'not authorized to update this task' USING ERRCODE = '42501';
  END IF;

  IF v_task.version <> _expected_version THEN
    RAISE EXCEPTION 'stale task version'
      USING ERRCODE = '40001',
            HINT = 'reload the task and retry';
  END IF;

  UPDATE public.tasks
  SET status = _new_status,
      version = version + 1
  WHERE id = _task_id
    AND version = _expected_version
  RETURNING * INTO v_updated;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'stale task version' USING ERRCODE = '40001';
  END IF;

  PERFORM app_hidden.write_audit(
    app_hidden.project_org(v_task.project_id),
    v_task.project_id,
    'task_status_transition',
    'task',
    v_task.id,
    jsonb_build_object('status', v_task.status, 'version', v_task.version),
    jsonb_build_object('status', v_updated.status, 'version', v_updated.version),
    '{}'::jsonb
  );

  RETURN v_updated;
END;
$$;

REVOKE ALL ON FUNCTION public.transition_task(uuid, integer, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.transition_task(uuid, integer, text) TO authenticated;

-- Used by invite-member Edge Function after caller authorization.
CREATE OR REPLACE FUNCTION public.create_invitation(
  _organisation_id uuid,
  _email text,
  _intended_role text,
  _token_hash_hex text,
  _expires_at timestamptz
)
RETURNS public.invitations
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  v_inv public.invitations%ROWTYPE;
  v_hash bytea;
BEGIN
  IF auth.uid() IS NULL THEN
    RAISE EXCEPTION 'not authenticated' USING ERRCODE = '42501';
  END IF;

  IF app_hidden.org_role(_organisation_id) NOT IN ('owner', 'admin') THEN
    RAISE EXCEPTION 'not authorized to invite' USING ERRCODE = '42501';
  END IF;

  IF _intended_role NOT IN ('admin', 'member', 'guest') THEN
    RAISE EXCEPTION 'invalid role' USING ERRCODE = '22023';
  END IF;

  IF app_hidden.org_role(_organisation_id) = 'admin' AND _intended_role = 'admin' THEN
    RAISE EXCEPTION 'admin cannot invite another admin' USING ERRCODE = '42501';
  END IF;

  IF _token_hash_hex IS NULL OR _token_hash_hex !~ '^[0-9a-f]{64}$' THEN
    RAISE EXCEPTION 'invalid token hash' USING ERRCODE = '22023';
  END IF;

  _email := lower(btrim(_email));
  v_hash := decode(_token_hash_hex, 'hex');

  INSERT INTO public.invitations (
    organisation_id, email, intended_role, token_hash, invited_by, expires_at
  ) VALUES (
    _organisation_id, _email, _intended_role, v_hash, auth.uid(), _expires_at
  )
  ON CONFLICT (organisation_id, email) WHERE accepted_at IS NULL AND revoked_at IS NULL
  DO UPDATE SET
    intended_role = EXCLUDED.intended_role,
    token_hash = EXCLUDED.token_hash,
    expires_at = EXCLUDED.expires_at,
    invited_by = EXCLUDED.invited_by
  RETURNING * INTO v_inv;

  PERFORM app_hidden.write_audit(
    _organisation_id, NULL, 'invitation_created', 'invitation', v_inv.id,
    NULL,
    jsonb_build_object('email', _email, 'role', _intended_role),
    '{}'::jsonb
  );

  RETURN v_inv;
END;
$$;

REVOKE ALL ON FUNCTION public.create_invitation(uuid, text, text, text, timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.create_invitation(uuid, text, text, text, timestamptz) TO authenticated;

-- Webhook persistence used by the Edge Function via service role.
CREATE OR REPLACE FUNCTION public.record_webhook_event(
  _provider text,
  _event_id text,
  _event_type text,
  _payload jsonb
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
  INSERT INTO public.webhook_events (provider, event_id, event_type, payload, status)
  VALUES (_provider, _event_id, _event_type, _payload, 'processed');
  RETURN true;
EXCEPTION
  WHEN unique_violation THEN
    RETURN false;
END;
$$;

REVOKE ALL ON FUNCTION public.record_webhook_event(text, text, text, jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.record_webhook_event(text, text, text, jsonb) TO service_role;
