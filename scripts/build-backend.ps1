$ErrorActionPreference = 'Stop'
$appRoot = Split-Path -Parent $PSScriptRoot
Push-Location $appRoot
try {
    $pythonLicense = & uv run --project backend python -c "import sys; from pathlib import Path; print(Path(sys.base_prefix) / 'LICENSE.txt')"
    if ($LASTEXITCODE -ne 0) { throw 'Cannot locate Python redistribution license.' }
    & uv run --project backend --group build pyinstaller `
        --noconfirm --clean --onedir --name keyloom `
        --distpath 'backend\dist' `
        --add-data ($pythonLicense + ';licenses') `
        --add-data ((Join-Path $appRoot 'assets\skills') + ';skills') `
        --workpath 'backend\build' --specpath 'backend' 'backend\keyloom_cli.py'
    if ($LASTEXITCODE -ne 0) { throw 'Vault backend packaging failed.' }
} finally {
    Pop-Location
}
