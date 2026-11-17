$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$version = (Get-Content -LiteralPath (Join-Path $root 'package.json') -Raw | ConvertFrom-Json).version
$artifacts = Join-Path $root 'artifacts'
$sources = @(
    @('stable-win-x64-Keyloom-Setup.zip', "keyloom-$version-windows-x64-setup.zip"),
    @('stable-win-x64-Keyloom.tar.zst', "keyloom-$version-windows-x64.tar.zst")
)
$hashes = @()
foreach ($pair in $sources) {
    $target = Join-Path $artifacts $pair[1]
    Copy-Item -LiteralPath (Join-Path $artifacts $pair[0]) -Destination $target -Force
    if ((Get-Item -LiteralPath $target).Length -lt 1000000) { throw 'Release artifact is unexpectedly small.' }
    $digest = (Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash.ToLowerInvariant()
    $hashes += "$digest  $($pair[1])"
}
[IO.File]::WriteAllLines((Join-Path $artifacts 'SHA256SUMS.txt'), $hashes, [Text.UTF8Encoding]::new($false))
Write-Output "Prepared Keyloom $version release assets and SHA256SUMS.txt"
