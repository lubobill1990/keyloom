@echo off
setlocal
where cl.exe >nul 2>nul
if errorlevel 1 (
  for /f "usebackq tokens=*" %%I in (`"%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do call "%%I\VC\Auxiliary\Build\vcvars64.bat" >nul
)
where cl.exe >nul 2>nul
if errorlevel 1 (
  echo Windows packaging requires Visual Studio C++ Build Tools, not Python. >&2
  exit /b 1
)
cl.exe /nologo /O1 /MT /W4 /WX /D_CRT_SECURE_NO_WARNINGS /Fo"dist-cli\keyloom-cli.obj" /Fe"dist-cli\keyloom.exe" "assets\keyloom-cli.c" shell32.lib /link /SUBSYSTEM:CONSOLE
exit /b %errorlevel%
