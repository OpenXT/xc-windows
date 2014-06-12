IF EXIST sign32 (rmdir /q /s sign32)
mkdir sign32
cd sign32
copy ..\build\i386\xennet.sys .
copy ..\build\i386\xennet6.sys .
copy ..\build\i386\xenwnet.sys .
copy ..\build\i386\xenwnet6.sys .
copy ..\build\i386\xenvbd.sys .
copy ..\build\i386\xenvesa-miniport.sys .
copy ..\build\i386\xenvesa-display.dll .
copy ..\build\i386\scsifilt.sys .
copy ..\build\i386\xenv4v.sys .
copy ..\build\i386\xevtchn.sys .
copy ..\build\i386\xenutil.sys .
copy ..\build\i386\xeninp.sys .
copy ..\build\i386\xenvesado.sys .
copy ..\xc-vusb\build\x86\xenvusb.sys .
copy ..\net\xennet.inf .
copy ..\wnet\xenwnet.inf .
copy ..\xc-vusb\build\x86\xenvusb.inf .
copy ..\install\WdfCoInstaller01009.dll .
copy ..\xenvbd\xenvbd.inf .
copy ..\xenvesa\xenvesa-xp.inf .
copy ..\xenvesa\xenvesa-lh.inf .
copy ..\xenv4v\xenv4v.inf .
copy ..\xenevtchn\xevtchn.inf .
copy ..\input\xeninp\xeninp.inf .
copy ..\xengfx\vesa\wddm\miniport\xenvesado.inf .
inf2cat /driver:. /os:2000,XP_X86,Server2003_X86,Vista_X86,Server2008_X86

@REM sign all of the catalog files
call ..\sign\%1 xennet.cat %2
call ..\sign\%1 xenwnet.cat %2
call ..\sign\%1 xenvusb.cat %2
call ..\sign\%1 xenvbd.cat %2
call ..\sign\%1 xenvesa-xp.cat %2
call ..\sign\%1 xenvesa-lh.cat %2
call ..\sign\%1 xenv4v.cat %2
call ..\sign\%1 xevtchn.cat %2
call ..\sign\%1 xeninp.cat %2
call ..\sign\%1 xenvesado.cat %2

@REM need to "embedded sign" boot start drivers
call ..\sign\%1 xevtchn.sys %2
call ..\sign\%1 xenv4v.sys %2
call ..\sign\%1 xenvbd.sys %2
call ..\sign\%1 xenvesa-miniport.sys %2
call ..\sign\%1 xenvesa-display.dll %2
call ..\sign\%1 scsifilt.sys %2
call ..\sign\%1 xennet.sys %2
call ..\sign\%1 xennet6.sys %2
call ..\sign\%1 xenwnet.sys %2
call ..\sign\%1 xenvusb.sys %2
call ..\sign\%1 xenwnet6.sys %2
call ..\sign\%1 xenutil.sys %2
call ..\sign\%1 xeninp.sys %2
call ..\sign\%1 xenvesado.sys %2

copy xennet.cat ..\net\.
copy xenwnet.cat ..\wnet\.
copy xenvusb.cat ..\xc-vusb\build\x86\.
copy xenvbd.cat ..\xenvbd\.
copy xenvesa-xp.cat ..\xenvesa\.
copy xenvesa-lh.cat ..\xenvesa\.
copy xenv4v.cat ..\xenv4v\.
copy xevtchn.cat ..\xenevtchn\.
copy xeninp.cat ..\input\xeninp\.
copy xenvesado.cat ..\xengfx\vesa\wddm\miniport\.
copy xenv4v.sys ..\build\i386
copy xenvbd.sys ..\build\i386
copy xenvesa-miniport.sys ..\build\i386
copy xenvesa-display.dll ..\build\i386
copy scsifilt.sys ..\build\i386
copy xevtchn.sys ..\build\i386
copy xennet.sys ..\build\i386
copy xennet6.sys ..\build\i386
copy xenwnet.sys ..\build\i386
copy xenvusb.sys ..\xc-vusb\build\x86\.
copy xenwnet6.sys ..\build\i386
copy xenutil.sys ..\build\i386
copy xeninp.sys ..\build\i386
copy xenvesado.sys ..\build\i386

cd ..
IF EXIST sign64 (rmdir /q /s sign64)
mkdir sign64
cd sign64
copy ..\build\amd64\xennet.sys .
copy ..\build\amd64\xennet6.sys .
copy ..\build\amd64\xenwnet.sys .
copy ..\build\amd64\xenwnet6.sys .
copy ..\build\amd64\xenvbd.sys .
copy ..\build\amd64\xenvesa-miniport.sys .
copy ..\build\amd64\xenvesa-display.dll .
copy ..\build\amd64\scsifilt.sys .
copy ..\build\amd64\xenv4v.sys .
copy ..\build\amd64\xevtchn.sys .
copy ..\build\amd64\xenutil.sys .
copy ..\build\amd64\xeninp.sys .
copy ..\build\amd64\xenvesado.sys .
copy ..\xc-vusb\build\x64\xenvusb.sys .
copy ..\net\xennet64.inf .
copy ..\wnet\xenwnet64.inf .
copy ..\xc-vusb\build\x64\xenvusb64.inf .
copy ..\install\WdfCoInstaller01009.dll .
copy ..\xenvbd\xenvbd64.inf .
copy ..\xenvesa\xenvesa-xp.inf .
copy ..\xenvesa\xenvesa-lh.inf .
copy ..\xenv4v\xenv4v64.inf .
copy ..\xenevtchn\xevtchn64.inf .
copy ..\input\xeninp\xeninp.inf .
copy ..\xengfx\vesa\wddm\miniport\xenvesado.inf .
inf2cat /driver:. /os:XP_X64,Server2003_X64,Vista_X64,Server2008_X64

@REM sign all of the catalog files
call ..\sign\%1 xennet.cat %2
call ..\sign\%1 xenwnet.cat %2
call ..\sign\%1 xenvusb.cat %2
call ..\sign\%1 xenvbd.cat %2
call ..\sign\%1 xenvesa-xp.cat %2
call ..\sign\%1 xenvesa-lh.cat %2
call ..\sign\%1 xenv4v.cat %2
call ..\sign\%1 xevtchn.cat %2
call ..\sign\%1 xeninp.cat %2
call ..\sign\%1 xenvesado.cat %2

@REM need to "embedded sign" boot start drivers
call ..\sign\%1 xevtchn.sys %2
call ..\sign\%1 xenv4v.sys %2
call ..\sign\%1 xenvbd.sys %2
call ..\sign\%1 xenvesa-miniport.sys %2
call ..\sign\%1 xenvesa-display.dll %2
call ..\sign\%1 scsifilt.sys %2
call ..\sign\%1 xennet.sys %2
call ..\sign\%1 xennet6.sys %2
call ..\sign\%1 xenwnet.sys %2
call ..\sign\%1 xenvusb.sys %2
call ..\sign\%1 xenwnet6.sys %2
call ..\sign\%1 xenutil.sys %2
call ..\sign\%1 xeninp.sys %2
call ..\sign\%1 xenvesado.sys %2

copy xennet.cat ..\net\xennet64.cat
copy xenwnet.cat ..\wnet\xenwnet64.cat
copy xenvusb.cat ..\xc-vusb\build\x64\.
copy xenvbd.cat ..\xenvbd\xenvbd64.cat
copy xenvesa-xp.cat ..\xenvesa\xenvesa-xp64.cat
copy xenvesa-lh.cat ..\xenvesa\xenvesa-lh64.cat
copy xenv4v.cat ..\xenv4v\xenv4v64.cat
copy xevtchn.cat ..\xenevtchn\xevtchn64.cat
copy xeninp.cat ..\input\xeninp\xeninp64.cat
copy xenvesado.cat ..\xengfx\vesa\wddm\miniport\xenvesado64.cat
copy xenvbd.sys ..\build\amd64
copy xenvesa-miniport.sys ..\build\amd64
copy xenvesa-display.dll ..\build\amd64
copy scsifilt.sys ..\build\amd64
copy xenv4v.sys ..\build\amd64
copy xevtchn.sys ..\build\amd64
copy xennet.sys ..\build\amd64
copy xennet6.sys ..\build\amd64
copy xenwnet.sys ..\build\amd64
copy xenvusb.sys ..\xc-vusb\build\x64\.
copy xenwnet6.sys ..\build\amd64
copy xenutil.sys ..\build\amd64
copy xeninp.sys ..\build\amd64
copy xenvesado.sys ..\build\amd64

cd ..
