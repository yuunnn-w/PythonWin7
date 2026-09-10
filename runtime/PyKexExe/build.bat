@echo off
rem ========================================================================
rem build.bat -- build PyKexExe (console + GUI variants), CRT-free, x64.
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

echo --- building PyKexExe.exe ^(console^) ---
cl %CFLAGS% PyKexExe.c /FePyKexExe.exe /link %LFLAGS% /SUBSYSTEM:CONSOLE /ENTRY:PykexEntryPoint || goto :fail

echo --- building PyKexExeW.exe ^(GUI^) ---
cl %CFLAGS% /DPYW7_GUI PyKexExe.c /FePyKexExeW.exe /link %LFLAGS% /SUBSYSTEM:WINDOWS /ENTRY:PykexEntryPoint || goto :fail

del /q *.obj 2>nul
echo OK: PyKexExe.exe PyKexExeW.exe
exit /b 0

:fail
echo BUILD FAILED
exit /b 1
