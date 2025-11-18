@echo off
setlocal enabledelayedexpansion

echo ================================================
echo   Roslyn-Powered Token Toolkit Compiler
echo ================================================
echo.

echo [*] Searching for Roslyn compiler...
echo.

set "ROSLYN_CSC="
set "FOUND=0"

REM Check Visual Studio 2022 locations
set "PATHS[0]=C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\Roslyn\csc.exe"
set "PATHS[1]=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\Roslyn\csc.exe"
set "PATHS[2]=C:\Program Files\Microsoft Visual Studio\2022\Professional\MSBuild\Current\Bin\Roslyn\csc.exe"
set "PATHS[3]=C:\Program Files\Microsoft Visual Studio\2022\Enterprise\MSBuild\Current\Bin\Roslyn\csc.exe"

REM Check Visual Studio 2019 locations
set "PATHS[4]=C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\MSBuild\Current\Bin\Roslyn\csc.exe"
set "PATHS[5]=C:\Program Files (x86)\Microsoft Visual Studio\2019\Professional\MSBuild\Current\Bin\Roslyn\csc.exe"
set "PATHS[6]=C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\MSBuild\Current\Bin\Roslyn\csc.exe"

REM Check Visual Studio 2017 locations
set "PATHS[7]=C:\Program Files (x86)\Microsoft Visual Studio\2017\Community\MSBuild\15.0\Bin\Roslyn\csc.exe"
set "PATHS[8]=C:\Program Files (x86)\Microsoft Visual Studio\2017\Professional\MSBuild\15.0\Bin\Roslyn\csc.exe"
set "PATHS[9]=C:\Program Files (x86)\Microsoft Visual Studio\2017\BuildTools\MSBuild\15.0\Bin\Roslyn\csc.exe"

REM Loop through paths
for /L %%i in (0,1,9) do (
    if exist "!PATHS[%%i]!" (
        set "ROSLYN_CSC=!PATHS[%%i]!"
        set "FOUND=1"
        goto :found
    )
)

:found
if !FOUND!==0 (
    echo [-] Roslyn compiler not found!
    echo.
    echo [!] Please ensure Visual Studio Build Tools 2022 is installed.
    echo [!] Download from: https://visualstudio.microsoft.com/downloads/
    echo.
    echo Installation steps:
    echo   1. Download "Build Tools for Visual Studio 2022"
    echo   2. Run installer
    echo   3. Select ".NET desktop build tools" workload
    echo   4. Install
    echo   5. Re-run this script
    echo.
    echo Expected location after install:
    echo   C:\Program Files ^(x86^)\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\Roslyn\csc.exe
    echo.
    pause
    exit /b 1
)

echo [+] Found Roslyn compiler!
echo [*] Location: !ROSLYN_CSC!
echo.

REM Check compiler version
echo [*] Compiler info:
"!ROSLYN_CSC!" /version 2>nul
echo.

echo ================================================
echo   Compiling Token Tools with Roslyn
echo ================================================
echo.

REM Compile all tools
set "SUCCESS=0"
set "FAILED=0"

echo [1/5] Compiling TokenEnumerator.exe...
"!ROSLYN_CSC!" /nologo /out:TokenEnumerator.exe TokenEnumerator.cs 2>&1 | findstr /C:"error" >nul
if !ERRORLEVEL!==0 (
    echo [-] Failed
    set /a FAILED+=1
) else (
    echo [+] Success
    set /a SUCCESS+=1
)
echo.

echo [2/5] Compiling TokenCreator.exe...
"!ROSLYN_CSC!" /nologo /out:TokenCreator.exe TokenCreator.cs 2>&1 | findstr /C:"error" >nul
if !ERRORLEVEL!==0 (
    echo [-] Failed
    set /a FAILED+=1
) else (
    echo [+] Success
    set /a SUCCESS+=1
)
echo.

echo [3/5] Compiling SqlTokenAuth.exe...
"!ROSLYN_CSC!" /nologo /out:SqlTokenAuth.exe SqlTokenAuth.cs 2>&1 | findstr /C:"error" >nul
if !ERRORLEVEL!==0 (
    echo [-] Failed
    set /a FAILED+=1
) else (
    echo [+] Success
    set /a SUCCESS+=1
)
echo.

echo [4/5] Compiling TokenTheft.exe...
"!ROSLYN_CSC!" /nologo /out:TokenTheft.exe TokenTheft.cs 2>&1 | findstr /C:"error" >nul
if !ERRORLEVEL!==0 (
    echo [-] Failed
    set /a FAILED+=1
) else (
    echo [+] Success
    set /a SUCCESS+=1
)
echo.

echo [5/6] Compiling TokenPrivileges.exe...
"!ROSLYN_CSC!" /nologo /out:TokenPrivileges.exe TokenPrivileges.cs 2>&1 | findstr /C:"error" >nul
if !ERRORLEVEL!==0 (
    echo [-] Failed
    set /a FAILED+=1
) else (
    echo [+] Success
    set /a SUCCESS+=1
)
echo.

echo [6/6] Compiling TokenCreator_Universal.exe...
"!ROSLYN_CSC!" /nologo /out:TokenCreator_Universal.exe TokenCreator_Universal.cs 2>&1 | findstr /C:"error" >nul
if !ERRORLEVEL!==0 (
    echo [-] Failed
    set /a FAILED+=1
) else (
    echo [+] Success
    set /a SUCCESS+=1
)
echo.

echo ================================================
echo   Compilation Summary
echo ================================================
echo.
echo Successful: !SUCCESS!/6
echo Failed:     !FAILED!/6
echo.

if exist TokenEnumerator.exe echo [+] TokenEnumerator.exe
if exist TokenCreator.exe echo [+] TokenCreator.exe
if exist SqlTokenAuth.exe echo [+] SqlTokenAuth.exe
if exist TokenTheft.exe echo [+] TokenTheft.exe
if exist TokenPrivileges.exe echo [+] TokenPrivileges.exe
if exist TokenCreator_Universal.exe echo [+] TokenCreator_Universal.exe

echo.

if !SUCCESS!==6 (
    echo [+] All tools compiled successfully!
    echo.
    echo Quick start:
    echo   TokenEnumerator.exe           - List process tokens
    echo   TokenTheft.exe -list          - Find stealable tokens
    echo   TokenPrivileges.exe -list     - Check your privileges
    echo   SqlTokenAuth.exe user pass DOMAIN sqlserver - SQL authentication
    echo   TokenCreator_Universal.exe user pass DOMAIN - Universal network auth
    echo.
) else (
    echo [!] Some compilations failed. Check errors above.
)

pause
