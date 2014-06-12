@REM add xentest.cer to the certificate store on this machine just in case it is not already there
REM certmgr.exe /add XenTest.cer /s PrivateCertStore

del /q /s sign32vusb
mkdir sign32vusb
cd sign32vusb

copy ..\xc-vusb\Drivers\xenvusb\Win7Release\xenvusb.sys .
copy ..\xc-vusb\Drivers\xenvusb\xenvusb.inf .
copy ..\install\WdfCoInstaller01009.dll .

inf2cat /driver:. /os:2000,XP_X86,Server2003_X86,Vista_X86,Server2008_X86

@REM sign all of the catalog files
signtool sign /f ..\sign\xentest.pfx /t http://timestamp.verisign.com/scripts/timestamp.dll xenvusb.cat

@REM need to "embedded sign" boot start drivers
Signtool sign /f ..\sign\xentest.pfx /t http://timestamp.verisign.com/scripts/timestamp.dll xenvusb.sys

copy xenvusb.cat ..\xc-vusb\Drivers\xenvusb\.
copy xenvusb.sys ..\xc-vusb\Drivers\xenvusb\Win7Release

cd ..
del /q /s sign64vusb
mkdir sign64vusb
cd sign64vusb

copy ..\xc-vusb\Drivers\xenvusb\x64\Win7Release\xenvusb.sys .
copy ..\xc-vusb\Drivers\xenvusb\xenvusb64.inf .
copy ..\install\WdfCoInstaller01009.dll .

inf2cat /driver:. /os:XP_X64,Server2003_X64,Vista_X64,Server2008_X64

@REM sign all of the catalog files
signtool sign /f ..\sign\xentest.pfx /t http://timestamp.verisign.com/scripts/timestamp.dll xenvusb.cat

@REM need to "embedded sign" boot start drivers
Signtool sign /f ..\sign\xentest.pfx /t http://timestamp.verisign.com/scripts/timestamp.dll xenvusb.sys

copy xenvusb.cat ..\xc-vusb\Drivers\xenvusb\xenvusb64.cat
copy xenvusb.sys ..\xc-vusb\Drivers\xenvusb\x64\Win7Release

cd ..
