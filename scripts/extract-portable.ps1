$ErrorActionPreference = 'Stop'
$appRoot = Split-Path -Parent $PSScriptRoot
$archive = Join-Path $appRoot 'artifacts\stable-win-x64-Keyloom.tar.zst'
$destination = Join-Path $appRoot 'build\portable-win-x64'
$staging = Join-Path $appRoot ('build\portable-staging-' + [Guid]::NewGuid().ToString())
if (Test-Path -LiteralPath $destination) {
    if ((Get-Item -LiteralPath $destination).Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw 'Portable output must not be a link or junction.'
    }
    $prefix = [IO.Path]::GetFullPath($destination) + '\'
    $running = @(Get-CimInstance Win32_Process | Where-Object {
        $_.ExecutablePath -and $_.ExecutablePath.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)
    })
    if ($running.Count) { throw 'Close the running portable instance before rebuilding.' }
}
New-Item -ItemType Directory -Path $staging | Out-Null
& tar -xf $archive -C $staging
if ($LASTEXITCODE -ne 0) { throw 'Portable application extraction failed. Close any running portable instance before rebuilding.' }
$stagedLauncher = Join-Path $staging 'Keyloom\bin\launcher.exe'
if (-not (Test-Path -LiteralPath $stagedLauncher)) { throw 'Staged portable launcher is missing.' }
if (Test-Path -LiteralPath $destination) {
    $previous = Join-Path $appRoot ('build\portable-previous-' + [Guid]::NewGuid().ToString())
    Move-Item -LiteralPath $destination -Destination $previous
    Write-Output "Previous local portable output preserved at: $previous"
}
Move-Item -LiteralPath $staging -Destination $destination
$launcher = Join-Path $destination 'Keyloom\bin\launcher.exe'
if (-not (Test-Path -LiteralPath $launcher)) { throw 'Portable application launcher is missing.' }
Write-Output "Portable application: $launcher"
