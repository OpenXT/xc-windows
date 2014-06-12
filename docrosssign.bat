REM Call this batch file with the build directory as the argument
cd %1

call findddk.bat
if "%ddk_path%"=="no ddk" goto end

set winqual_path="c:\program files\microsoft winqual submission tool 2"
if not exist %winqual_path% if exist "c:\program files\microsoft winqual submission tool" set winqual_path="c:\program files\microsoft winqual submission tool"
path=%path%;%winqual_path%
set winqual_path=
path=%path%;%ddk_path%\bin\catalog
sign\sign.cmd crosssign.bat %2

:end
