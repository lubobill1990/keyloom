$ErrorActionPreference = 'Stop'
Push-Location (Split-Path -Parent $PSScriptRoot)
try {
    & bun scripts/build-cli.ts
    if ($LASTEXITCODE -ne 0) { throw 'Bun CLI build failed.' }
} finally { Pop-Location }
