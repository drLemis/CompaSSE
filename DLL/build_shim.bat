@echo off
setlocal
call "%~dp0find_vs.bat"
if errorlevel 1 exit /b 1
call "%VCVARS%" amd64
if errorlevel 1 exit /b 1
if not exist build mkdir build
cl /nologo /O2 /W3 /EHsc /LD main.cpp hooks.cpp decoder_detect.cpp transcode.cpp minhook\src\hook.c minhook\src\trampoline.c minhook\src\buffer.c minhook\src\hde\hde64.c /I minhook\include /I minhook\src /Fo:build\ /Fe:build\!CompaSSE.dll /link advapi32.lib
if errorlevel 1 exit /b 1
echo BUILD OK