@echo off

set ddk_path="no ddk"
if exist c:\winddk\6000 set ddk_path=c:\winddk\6000
if exist c:\winddk\6001.18000 set ddk_path=c:\winddk\6001.18000
if exist c:\winddk\6001.18001 set ddk_path=c:\winddk\6001.18001
if exist c:\winddk\6001.18002 set ddk_path=c:\winddk\6001.18002
if exist c:\winddk\7600.16385.0 set ddk_path=c:\winddk\7600.16385.0

if "%ddk_path%"=="no ddk" goto no_ddk
goto found_ddk

:no_ddk
echo "Cannot find a DDK in either c:\winddk\6001.18002 c:\winddk\6001.18001, c:\winddk\6001.18000 or c:\winddk\6000"
goto end

:found_ddk
echo ddk is %ddk_path%

:end
@echo on
