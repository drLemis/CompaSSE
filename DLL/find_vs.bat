@echo off
rem Sets VCVARS to vcvarsall.bat. No setlocal here: the caller needs it.
set "VCVARS="
if exist "%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" (
  for /f "usebackq delims=" %%i in (`"%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do (
    if exist "%%i\VC\Auxiliary\Build\vcvarsall.bat" set "VCVARS=%%i\VC\Auxiliary\Build\vcvarsall.bat"
  )
)
if not defined VCVARS (
  for %%p in ("%ProgramFiles(x86)%\Microsoft Visual Studio\2022\BuildTools" "%ProgramFiles%\Microsoft Visual Studio\2022\Community" "%ProgramFiles%\Microsoft Visual Studio\2022\Professional" "%ProgramFiles%\Microsoft Visual Studio\2022\Enterprise") do (
    if not defined VCVARS if exist "%%~p\VC\Auxiliary\Build\vcvarsall.bat" set "VCVARS=%%~p\VC\Auxiliary\Build\vcvarsall.bat"
  )
)
if not defined VCVARS (
  echo vcvarsall.bat not found - install Visual Studio 2022 C++ build tools 1>&2
  exit /b 1
)
