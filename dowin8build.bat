@echo off
REM %1 - Visual Studio Directory
REM %2 - Build base directory
REM %3 - Release or debug build - fre|chk
REM %4 - Build architecture - x86|x64

REM check for usage
IF NOT [%1]==[] goto CONTINUE
echo.
echo	Usage:
echo	Visual Studio Directory
echo	Build base directory
echo	Release or debug build  - "fre|chk"
echo	Build architecture      - "x86|x64"
echo
goto DONE

:CONTINUE
set XEN_CONFIG=""
IF /I "%3"== "fre" set XEN_CONFIG="Win8 Release"
IF /I "%3"== "chk" set XEN_CONFIG="Win8 Debug"
if %XEN_CONFIG%=="" goto ERROR

set PLATFORM_NAME=""
if  /I "%4"=="x86"   set PLATFORM_NAME=Win32
if  /I "%4"=="x64" set PLATFORM_NAME=x64
if %PLATFORM_NAME%=="" goto ERROR

if "%BuildPlatform%"=="" goto START
if	/I "%PLATFORM_NAME%"==%BuildPlatform% goto START_BUILD

echo.
echo ERROR: This window already has a differnt DDK build environment.  Please open
echo		a new window.
echo
goto SET_DIR


:START
set BuildPlatform="%PLATFORM_NAME%"	
echo Setting the sdk/ddk environment to %PLATFORM_NAME%
set VS_ENV=%1\VC\vcvarsall.bat 
if /I %PLATFORM_NAME%==x64 call %VS_ENV% x86_amd64
if /I %PLATFORM_NAME%==Win32 call %VS_ENV% x86

:START_BUILD
cd /d %2

set USERNAME=OpenXT

echo.
echo	BUILD:
echo		Configuration - %XEN_CONFIG%
echo		Platform      - %PLATFORM_NAME%
echo

msbuild /m /t:clean /t:build /p:Configuration=%XEN_CONFIG% /p:Platform=%PLATFORM_NAME% WindowsEight.sln  
GOTO SET_DIR

:ERROR
echo.
echo ERROR:	Bad configuration or platform parameter encountered.
echo		Configuration %3 should be either fre or chk.
echo		Platform %4 should be either x86 or x64
echo

:SET_DIR
cd /d %2

:DONE
