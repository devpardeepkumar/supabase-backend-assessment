-- Private project-files bucket + Storage RLS keyed off the same project-access helper.
-- Path convention: {organisation_id}/{project_id}/{file_id}

INSERT INTO storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
VALUES (
  'project-files',
  'project-files',
  false,
  52428800,
  ARRAY[
    'image/png',
    'image/jpeg',
    'image/webp',
    'application/pdf',
    'text/plain',
    'application/zip'
  ]
)
ON CONFLICT (id) DO UPDATE
SET public = false,
    file_size_limit = 52428800,
    allowed_mime_types = EXCLUDED.allowed_mime_types;

CREATE OR REPLACE FUNCTION app_hidden.storage_project_id(_name text)
RETURNS uuid
LANGUAGE plpgsql
STABLE
SET search_path = pg_catalog, public
AS $$
DECLARE
  v_project text;
BEGIN
  v_project := split_part(_name, '/', 2);
  IF v_project ~ '^[0-9a-fA-F-]{36}$' THEN
    RETURN v_project::uuid;
  END IF;
  RETURN NULL;
END;
$$;

CREATE OR REPLACE FUNCTION app_hidden.storage_org_id(_name text)
RETURNS uuid
LANGUAGE plpgsql
STABLE
SET search_path = pg_catalog, public
AS $$
DECLARE
  v_org text;
BEGIN
  v_org := split_part(_name, '/', 1);
  IF v_org ~ '^[0-9a-fA-F-]{36}$' THEN
    RETURN v_org::uuid;
  END IF;
  RETURN NULL;
END;
$$;

CREATE OR REPLACE FUNCTION app_hidden.storage_path_matches_project(_name text)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
  SELECT EXISTS (
    SELECT 1
    FROM public.projects p
    WHERE p.id = app_hidden.storage_project_id(_name)
      AND p.organisation_id = app_hidden.storage_org_id(_name)
  );
$$;

DROP POLICY IF EXISTS project_files_select ON storage.objects;
DROP POLICY IF EXISTS project_files_insert ON storage.objects;
DROP POLICY IF EXISTS project_files_update ON storage.objects;
DROP POLICY IF EXISTS project_files_delete ON storage.objects;

CREATE POLICY project_files_select ON storage.objects
  FOR SELECT TO authenticated
  USING (
    bucket_id = 'project-files'
    AND app_hidden.storage_path_matches_project(name)
    AND app_hidden.can_view_project(app_hidden.storage_project_id(name))
  );

CREATE POLICY project_files_insert ON storage.objects
  FOR INSERT TO authenticated
  WITH CHECK (
    bucket_id = 'project-files'
    AND app_hidden.storage_path_matches_project(name)
    AND app_hidden.can_write_project_content(app_hidden.storage_project_id(name))
    AND owner = auth.uid()
  );

CREATE POLICY project_files_update ON storage.objects
  FOR UPDATE TO authenticated
  USING (
    bucket_id = 'project-files'
    AND app_hidden.can_write_project_content(app_hidden.storage_project_id(name))
  )
  WITH CHECK (
    bucket_id = 'project-files'
    AND app_hidden.storage_path_matches_project(name)
    AND app_hidden.storage_org_id(name) = app_hidden.storage_org_id(name)
    AND app_hidden.storage_project_id(name) IS NOT DISTINCT FROM app_hidden.storage_project_id(name)
    AND app_hidden.can_write_project_content(app_hidden.storage_project_id(name))
  );

-- WITH CHECK above is tautological on NEW only. Freeze moves with a trigger-like check
-- by comparing to the existing row via a constraint function on UPDATE using OLD.
CREATE OR REPLACE FUNCTION app_hidden.storage_update_same_project()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
  IF NEW.bucket_id = 'project-files' AND (
    app_hidden.storage_org_id(NEW.name) IS DISTINCT FROM app_hidden.storage_org_id(OLD.name)
    OR app_hidden.storage_project_id(NEW.name) IS DISTINCT FROM app_hidden.storage_project_id(OLD.name)
    OR NEW.bucket_id IS DISTINCT FROM OLD.bucket_id
  ) THEN
    RAISE EXCEPTION 'cannot move project files across organisations or projects';
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS storage_objects_no_cross_project ON storage.objects;
CREATE TRIGGER storage_objects_no_cross_project
  BEFORE UPDATE ON storage.objects
  FOR EACH ROW
  EXECUTE FUNCTION app_hidden.storage_update_same_project();

CREATE POLICY project_files_delete ON storage.objects
  FOR DELETE TO authenticated
  USING (
    bucket_id = 'project-files'
    AND (
      owner = auth.uid()
      OR app_hidden.project_role(app_hidden.storage_project_id(name)) = 'manager'
      OR app_hidden.org_role(app_hidden.storage_org_id(name)) IN ('owner', 'admin')
    )
  );

-- Realtime: private project:<uuid> topics, same can_view_project decision.
CREATE OR REPLACE FUNCTION app_hidden.realtime_project_id()
RETURNS uuid
LANGUAGE plpgsql
STABLE
SET search_path = pg_catalog, public
AS $$
DECLARE
  v_topic text;
  v_id text;
BEGIN
  v_topic := realtime.topic();
  IF v_topic IS NULL OR v_topic NOT LIKE 'project:%' THEN
    RETURN NULL;
  END IF;
  v_id := substring(v_topic FROM 9);
  IF v_id ~ '^[0-9a-fA-F-]{36}$' THEN
    RETURN v_id::uuid;
  END IF;
  RETURN NULL;
END;
$$;

DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM information_schema.tables
    WHERE table_schema = 'realtime' AND table_name = 'messages'
  ) THEN
    EXECUTE 'DROP POLICY IF EXISTS project_broadcast_select ON realtime.messages';
    EXECUTE $pol$
      CREATE POLICY project_broadcast_select ON realtime.messages
        FOR SELECT TO authenticated
        USING (
          app_hidden.realtime_project_id() IS NOT NULL
          AND app_hidden.can_view_project(app_hidden.realtime_project_id())
        )
    $pol$;

    EXECUTE 'DROP POLICY IF EXISTS project_broadcast_insert ON realtime.messages';
    EXECUTE $pol$
      CREATE POLICY project_broadcast_insert ON realtime.messages
        FOR INSERT TO authenticated
        WITH CHECK (
          app_hidden.realtime_project_id() IS NOT NULL
          AND app_hidden.can_view_project(app_hidden.realtime_project_id())
        )
    $pol$;
  END IF;
END;
$$;

CREATE OR REPLACE FUNCTION app_hidden.publish_task_change()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  v_row public.tasks%ROWTYPE;
  v_event text;
BEGIN
  v_row := COALESCE(NEW, OLD);
  v_event := lower(TG_OP);
  PERFORM realtime.send(
    jsonb_build_object(
      'event', v_event,
      'id', v_row.id,
      'project_id', v_row.project_id,
      'status', v_row.status,
      'position', v_row.position,
      'version', v_row.version,
      'assignee_id', v_row.assignee_id,
      'updated_at', v_row.updated_at
    ),
    'task_changed',
    'project:' || v_row.project_id::text,
    false
  );
  RETURN COALESCE(NEW, OLD);
EXCEPTION
  WHEN OTHERS THEN
    RETURN COALESCE(NEW, OLD);
END;
$$;

CREATE OR REPLACE FUNCTION app_hidden.publish_comment_change()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  v_row public.comments%ROWTYPE;
  v_event text;
BEGIN
  v_row := COALESCE(NEW, OLD);
  v_event := lower(TG_OP);
  PERFORM realtime.send(
    jsonb_build_object(
      'event', v_event,
      'id', v_row.id,
      'project_id', v_row.project_id,
      'task_id', v_row.task_id,
      'author_id', v_row.author_id,
      'created_at', v_row.created_at
    ),
    'comment_changed',
    'project:' || v_row.project_id::text,
    false
  );
  RETURN COALESCE(NEW, OLD);
EXCEPTION
  WHEN OTHERS THEN
    RETURN COALESCE(NEW, OLD);
END;
$$;

DROP TRIGGER IF EXISTS tasks_broadcast ON public.tasks;
CREATE TRIGGER tasks_broadcast
  AFTER INSERT OR UPDATE OR DELETE ON public.tasks
  FOR EACH ROW
  EXECUTE FUNCTION app_hidden.publish_task_change();

DROP TRIGGER IF EXISTS comments_broadcast ON public.comments;
CREATE TRIGGER comments_broadcast
  AFTER INSERT OR UPDATE OR DELETE ON public.comments
  FOR EACH ROW
  EXECUTE FUNCTION app_hidden.publish_comment_change();

GRANT USAGE ON SCHEMA app_hidden TO authenticated;
GRANT EXECUTE ON FUNCTION app_hidden.storage_project_id(text) TO authenticated;
GRANT EXECUTE ON FUNCTION app_hidden.storage_org_id(text) TO authenticated;
GRANT EXECUTE ON FUNCTION app_hidden.storage_path_matches_project(text) TO authenticated;
GRANT EXECUTE ON FUNCTION app_hidden.realtime_project_id() TO authenticated;
