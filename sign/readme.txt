This provides the steps that must be taken to install pv-drivers on x64 Windows version of Vista and later.  These versions of windows will not allow unsigned drivers to load and since xevtchn.sys is a boot start driver, this will prevent you from booting.

You can install unsigned drivers on your vm and for each boot choose F8->disable driver signature enforcement.  But you must do this every boot.

Or you can test sign the drivers yourself and setup your vm to trust the your test certificate.  This will allow you to install your test signed drivers and boot normally.

To use the test signing batch files you will need to create your own test key pair and certificate (the default used in the past was an RSA 1024 bit key). Once you create the key and certificate, copy them into the "sign" directory as xentest.cer and xentest.pfx. If you specify a key usage OID, ensure that code signing is one of the usages.

Before you begin you have to install the winqual sibmission tool in order to get the inf2cat executable.  This can be found by going to the following link: https://winqual.microsoft.com/Help/Inf2cat_FAQ.htm
You will also need to do "path=%path%;c:\program files\microsoft winqual submission tool" to add this to your path.

On the build machine:
1) build 32-bit and 64-bit drivers
2) Run "sign\signtest.cmd" from the root of the xc-windows enlistment to test sign the drivers
3) Run "makensis.exe xensetup.nsi" in the install directory to create the xensetup.exe package.

On the client vm:
1) On Vista or later run "bcdedit /set testsigning on"
2) Reboot
3) Install the test certificates.  For this you need to get certmgr.exe and xentest.cer from the sign directory.
    3a) Run "certmgr.exe /add xentest.cer /s /r localmachine root"
    3b) Run "certmgr.exe /add xentest.cer /s /r localmachine trustedpublisher"
4) Install the test signed pv-drivers.
