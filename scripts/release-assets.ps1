$ErrorActionPreference = 'Stop'
Push-Location (Split-Path -Parent $PSScriptRoot)
try {
    & bun scripts/release-assets.ts
    if ($LASTEXITCODE -ne 0) { throw 'Release asset packaging failed.' }
} finally { Pop-Location }
