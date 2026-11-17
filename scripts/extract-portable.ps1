$ErrorActionPreference = 'Stop'
Push-Location (Split-Path -Parent $PSScriptRoot)
try {
    & bun scripts/extract-portable.ts
    if ($LASTEXITCODE -ne 0) { throw 'Portable extraction failed.' }
} finally { Pop-Location }
