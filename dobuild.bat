REM %1 - DDK location
REM %2 - Build base directory
REM %3 - Release or debug build - fre|chk
REM %4 - Build architecture - x86|x64

call %1\bin\setenv.bat %1 %3 WLH %4 no_oacr || exit /b 1

cd /d %2

IF NOT EXIST tmp GOTO SKIP_REMOVE 
rmdir /s/q tmp 
:SKIP_REMOVE 

mkdir tmp
set tmp=%2\tmp
set temp=%2\tmp

set USERNAME=OpenXT

REM beware https://github.com/OpenXT/xc-windows/issues/3 if you want to make
REM this faster by removing the c and z flags to get incremental builds
build -begwcz 2>&1 || exit /b 2
