set STAMPINF_VERSION=%3
for /f %%x in ('wmic path win32_utctime get /format:list ^| findstr "="') do set %%x
if %Day% LSS 10 set Day=0%Day%
if %Month% LSS 10 set Month=0%Month%
echo Stamping with day %Day%
echo Stamping with Month %Month%
echo Stamping with Year %Year%
cd /d %2
%1\bin\x86\stampinf -f xenevtchn\xevtchn.inf -d %Month%/%Day%/%Year% -v || exit /b 1
%1\bin\x86\stampinf -f xenevtchn\xevtchn64.inf -d %Month%/%Day%/%Year% -v || exit /b 1
%1\bin\x86\stampinf -f net\xennet.inf -d %Month%/%Day%/%Year% -v || exit /b 1
%1\bin\x86\stampinf -f net\xennet64.inf -d %Month%/%Day%/%Year% -v || exit /b 1
%1\bin\x86\stampinf -f xenvbd\xenvbd.inf -d %Month%/%Day%/%Year% -v || exit /b 1
%1\bin\x86\stampinf -f xenvbd\xenvbd64.inf -d %Month%/%Day%/%Year% -v || exit /b 1
%1\bin\x86\stampinf -f xenvesa\xenvesa-xp.inf -d %Month%/%Day%/%Year% -v || exit /b 1
%1\bin\x86\stampinf -f xenvesa\xenvesa-lh.inf -d %Month%/%Day%/%Year% -v || exit /b 1
%1\bin\x86\stampinf -f input\xeninp\xeninp.inf -d %Month%/%Day%/%Year% -v || exit /b 1
%1\bin\x86\stampinf -f input\xenm2b\xenm2b.inf -d %Month%/%Day%/%Year% -v || exit /b 1
%1\bin\x86\stampinf -f wnet\xenwnet.inf -d %Month%/%Day%/%Year% -v || exit /b 1
%1\bin\x86\stampinf -f wnet\xenwnet64.inf -d %Month%/%Day%/%Year% -v || exit /b 1
%1\bin\x86\stampinf -f xengfx\vesa\wddm\miniport\xenVesaDO.inf -d %Month%/%Day%/%Year% -v || exit /b 1
%1\bin\x86\stampinf -f xengfx\wddm\xengfx32.inf -d %Month%/%Day%/%Year% -v || exit /b 1
%1\bin\x86\stampinf -f xengfx\wddm\xengfx64.inf -d %Month%/%Day%/%Year% -v || exit /b 1
%1\bin\x86\stampinf -f xengfx\xddm\xengfx-lh.inf -d %Month%/%Day%/%Year% -v || exit /b 1
%1\bin\x86\stampinf -f xengfx\xddm\xengfx-xp.inf -d %Month%/%Day%/%Year% -v || exit /b 1
%1\bin\x86\stampinf -f xenv4v\xenv4v.inf -d %Month%/%Day%/%Year% -v || exit /b 1
%1\bin\x86\stampinf -f xenv4v\xenv4v64.inf -d %Month%/%Day%/%Year% -v || exit /b 1
