REM first arg is DDK location, second is the build directory

call %1\bin\setenv.bat %1 free WLH %3

cd /d %2

IF NOT EXIST tmp GOTO SKIP_REMOVE 
rmdir /s/q tmp 
:SKIP_REMOVE 

mkdir tmp
set tmp=%2\tmp
set temp=%2\tmp

set USERNAME=OpenXT

build -bczgw

