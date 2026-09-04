@echo off
rem ========================================================================
rem build.bat -- build PyKexLdr (console + GUI variants), CRT-free, x64.
rem Requires Visual Studio 2022 (vcvars64). Edit VCVARS below if installed
rem elsewhere.
rem ========================================================================
setlocal
set VCVARS=C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat
if not exist "%VCVARS%" (
    echo vcvars64.bat not found at:
    echo   %VCVARS%
    echo Edit VCVARS in this script to point at your VS2022 installation.
    exit /b 1
)
call "%VCVARS%" >nul
if errorlevel 1 exit /b 1

set CFLAGS=/nologo /O1 /GS- /W3 /D_UNICODE /DUNICODE /DWIN32_LEAN_AND_MEAN
set LFLAGS=/nologo /NODEFAULTLIB /MACHINE:X64 kernel32.lib

echo --- building PyKexLdr.exe ^(console^) ---
cl %CFLAGS% PyKexLdr.c /FePyKexLdr.exe /link %LFLAGS% /SUBSYSTEM:CONSOLE /ENTRY:PykexEntryPoint || goto :fail

echo --- building PyKexLdrW.exe ^(GUI^) ---
cl %CFLAGS% /DPYW7_GUI PyKexLdr.c /FePyKexLdrW.exe /link %LFLAGS% /SUBSYSTEM:WINDOWS /ENTRY:PykexEntryPoint || goto :fail

del /q *.obj 2>nul
echo OK: PyKexLdr.exe PyKexLdrW.exe
exit /b 0

:fail
echo BUILD FAILED
exit /b 1
