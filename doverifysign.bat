@echo ON

IF "%~1"=="" GOTO PathLess
cd sign32
@REM Check signature on catalog files
"%~1"\signtool.exe verify /kp /v xennet.cat xenwnet.cat xenvbd.cat xenvesa-xp.cat xenvesa-lh.cat xenv4v.cat xevtchn.cat xeninp.cat
IF ERRORLEVEL 1 GOTO Exit
@REM Check embedded signature on boot start drivers
"%~1"\signtool verify /kp /v xevtchn.sys xenv4v.sys xenvbd.sys xenvesa-miniport.sys xenvesa-display.dll scsifilt.sys xennet.sys xennet6.sys xenwnet.sys xenwnet6.sys xenutil.sys xeninp.sys
IF ERRORLEVEL 1 GOTO Exit

cd ..\sign64
@REM Check signature on catalog files
"%~1"\signtool verify /kp /v xennet.cat xenwnet.cat xenvbd.cat xenvesa-xp.cat xenvesa-lh.cat xenv4v.cat xevtchn.cat xeninp.cat 
IF ERRORLEVEL 1 GOTO Exit
@REM Check embedded signature on boot start drivers
"%~1"\signtool verify /kp /v xevtchn.sys xenv4v.sys xenvbd.sys xenvesa-miniport.sys xenvesa-display.dll scsifilt.sys xennet.sys xennet6.sys xenwnet.sys xenwnet6.sys xenutil.sys xeninp.sys
GOTO Exit

:PathLess
cd sign32
@REM Check signature on catalog files
signtool verify /kp /v xennet.cat xenwnet.cat xenvbd.cat xenvesa-xp.cat xenvesa-lh.cat xenv4v.cat xevtchn.cat xeninp.cat
IF ERRORLEVEL 1 GOTO Exit
@REM Check embedded signature on boot start drivers
signtool verify /kp /v xevtchn.sys xenv4v.sys xenvbd.sys xenvesa-miniport.sys xenvesa-display.dll scsifilt.sys xennet.sys xennet6.sys xenwnet.sys xenwnet6.sys xenutil.sys xeninp.sys
IF ERRORLEVEL 1 GOTO Exit

cd ..\sign64
@REM Check signature on catalog files
signtool verify /kp /v xennet.cat xenwnet.cat xenvbd.cat xenvesa-xp.cat xenvesa-lh.cat xenv4v.cat xevtchn.cat xeninp.cat 
IF ERRORLEVEL 1 GOTO Exit
@REM Check embedded signature on boot start drivers
signtool verify /kp /v xevtchn.sys xenv4v.sys xenvbd.sys xenvesa-miniport.sys xenvesa-display.dll scsifilt.sys xennet.sys xennet6.sys xenwnet.sys xenwnet6.sys xenutil.sys xeninp.sys
IF ERRORLEVEL 1 GOTO Exit

:Exit
@EXIT %ERRORLEVEL%
