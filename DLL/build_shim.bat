@echo off
setlocal
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" amd64
if errorlevel 1 exit /b 1
if not exist build mkdir build
cl /nologo /O2 /W3 /EHsc /LD main.cpp hooks.cpp decoder_detect.cpp transcode.cpp postload_scan.cpp minhook\src\hook.c minhook\src\trampoline.c minhook\src\buffer.c minhook\src\hde\hde64.c /I minhook\include /I minhook\src /Fe:build\!CompaSSE.dll /link advapi32.lib
if errorlevel 1 exit /b 1
cl /nologo /O2 /W3 /EHsc test_transcode.cpp transcode.cpp /Fe:build\test_transcode.exe
if errorlevel 1 exit /b 1
echo BUILD OK