$ErrorActionPreference = 'Stop'
$appRoot = Split-Path -Parent $PSScriptRoot
$archive = Join-Path $appRoot 'artifacts\stable-win-x64-Keyloom.tar.zst'
$destination = Join-Path $appRoot 'build\portable-win-x64'
New-Item -ItemType Directory -Path $destination -Force | Out-Null
& tar -xf $archive -C $destination
if ($LASTEXITCODE -ne 0) { throw 'Portable application extraction failed. Close any running portable instance before rebuilding.' }
$launcher = Join-Path $destination 'Keyloom\bin\launcher.exe'
if (-not (Test-Path -LiteralPath $launcher)) { throw 'Portable application launcher is missing.' }
Write-Output "Portable application: $launcher"
