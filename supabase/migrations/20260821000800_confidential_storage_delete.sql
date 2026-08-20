-- Confidential access must apply to Storage deletes, not only SELECT.
-- Org admins may delete files only when they can already view the project.

CREATE OR REPLACE FUNCTION app_hidden.can_delete_project_file(_project_id uuid, _uploaded_by uuid)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
  SELECT
    _uploaded_by = auth.uid()
    OR app_hidden.project_role(_project_id) = 'manager'
    OR app_hidden.org_role(app_hidden.project_org(_project_id)) = 'owner'
    OR (
      app_hidden.org_role(app_hidden.project_org(_project_id)) = 'admin'
      AND app_hidden.can_view_project(_project_id)
    );
$$;

REVOKE ALL ON FUNCTION app_hidden.can_delete_project_file(uuid, uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app_hidden.can_delete_project_file(uuid, uuid) TO authenticated;

DROP POLICY IF EXISTS project_files_delete ON public.project_files;
CREATE POLICY project_files_delete ON public.project_files
  FOR DELETE TO authenticated
  USING (app_hidden.can_delete_project_file(project_id, uploaded_by));

DROP POLICY IF EXISTS project_files_delete ON storage.objects;
CREATE POLICY project_files_delete ON storage.objects
  FOR DELETE TO authenticated
  USING (
    bucket_id = 'project-files'
    AND app_hidden.can_delete_project_file(
      app_hidden.storage_project_id(name),
      owner
    )
  );
