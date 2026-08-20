#!/usr/bin/env bash
# Run pgTAP tests inside the already-running local Postgres container.
# Avoids `supabase test db`, which pulls a separate pg_prove image.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
for file in 01_adversarial.sql 02_confidential.sql 03_storage.sql 04_addendum.sql 05_requirement.sql; do
  echo "=== $file ==="
  docker exec -i supabase_db_supabase psql -U postgres -v ON_ERROR_STOP=1 \
    < "$root/supabase/tests/$file"
done
echo "All database tests completed."
