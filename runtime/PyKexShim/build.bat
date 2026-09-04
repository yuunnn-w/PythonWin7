@echo off
rem ========================================================================
rem build.bat -- build PyKexShim.dll, CRT-free, x64, kernel32 imports only.
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
set LFLAGS=/nologo /NODEFAULTLIB /MACHINE:X64 /DLL kernel32.lib

echo --- building PyKexShim.dll ---
cl %CFLAGS% PyKexShim.c /FePyKexShim.dll /link %LFLAGS% /ENTRY:DllMain || goto :fail

del /q *.obj *.exp *.lib 2>nul
echo OK: PyKexShim.dll
exit /b 0

:fail
echo BUILD FAILED
exit /b 1
