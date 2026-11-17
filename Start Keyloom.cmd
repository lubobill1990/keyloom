@echo off
setlocal
set "APP_DIR=%~dp0build\portable-win-x64\Keyloom\bin"
if not exist "%APP_DIR%\launcher.exe" set "APP_DIR=%~dp0build\dev-win-x64\Keyloom-dev\bin"
if not exist "%APP_DIR%\launcher.exe" (
  echo Run "bun run build" or "bun run build:release" first, or install a release from GitHub.
  pause
  exit /b 1
)
pushd "%APP_DIR%"
start "" "%APP_DIR%\launcher.exe"
popd
