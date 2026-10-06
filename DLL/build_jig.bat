@echo off
setlocal
call "%~dp0find_vs.bat"
if errorlevel 1 exit /b 1
call "%VCVARS%" amd64
if errorlevel 1 exit /b 1
if not exist build mkdir build
set RC_SRC=jig_version.rc
if exist build\jig_version.rc set RC_SRC=build\jig_version.rc
rc /nologo /fo build\jig_version.res %RC_SRC%
if errorlevel 1 exit /b 1
cl /nologo /O2 /W3 /EHsc jig_host.cpp minhook\src\hook.c minhook\src\buffer.c minhook\src\trampoline.c minhook\src\hde\hde64.c build\jig_version.res /I minhook\include /I minhook\src /Fo:build\ /Fe:build\jig_host.exe
if errorlevel 1 exit /b 1
echo JIG OK
