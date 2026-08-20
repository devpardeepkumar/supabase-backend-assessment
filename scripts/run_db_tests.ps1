# Run pgTAP tests inside the already-running local Postgres container.
# Avoids `supabase test db`, which pulls a separate pg_prove image.
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$tests = Join-Path $root "supabase\tests"
$files = @(
  "01_adversarial.sql",
  "02_confidential.sql",
  "03_storage.sql",
  "04_addendum.sql",
  "05_requirement.sql"
)

foreach ($file in $files) {
  Write-Host "=== $file ==="
  Get-Content (Join-Path $tests $file) |
    docker exec -i supabase_db_supabase psql -U postgres -v ON_ERROR_STOP=1
  if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}

Write-Host "All database tests completed."
