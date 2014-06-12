Test


Windows PV Stack
----------------


Overview
--------

The Windows PV Stack contains 4 kernel drivers (xenevtchn.sys, xenvbd.sys, xennet.sys, ntbootdd.sys) and 
user-mode components (xs.dll and xenservice.exe)


Build requirements
-------------------
- Windows Driver Kit ( build 6000 )
- Package installer from http://nsis.sourceforge.net/Main_Page
- Package installer overlay nsis-2.18-log.zip for LogText, also from NSIS
- Mercurial 0.9 (http://www.selenic.com)

The NSIS files are available locally in /usr/groups/linus/distfiles/windows-build


Checkin Notification
--------------------

Every push to win-drivers.hg repository will cause an email to be sent out to dev-windows alias with the commit information.
To make sure the email is sent using your alias, add the following line to your mercurial configuration file:
(The mercurial configuration file in Windows is *not* .hgrc but "%HOMEPATH%\Mercurial.ini")

[ui]
username = Name <userid@xensource.com>

e.g. John Smith <jsmith@xensource.com>

Runtime requirements
--------------------

- Xen baseline (xs-xen.hg + patchqueue) (Host)
- VT box
- w2k3 standard or enterprise (guest OS)


A) Building the drivers
1) install DDK
2) install the installer and its plugins 
	- to install the plugins, extract the zip file, goto Registry\Desktop directory and run the install.exe
	- Extract nsis-2.18-log.zip to overwrite files in the original NSIS installation
3) download the source from http://hg.uk.xensource.com/closed/win-drivers.hg repository (this is a intranet site ie you may need to VPN in)
4) cd to windows\ dir
5) bring up the ddk build windows and run "build -bcz" to build the drivers and user-mode components



B) Building the installer package containing the drivers and user-mode components (xensetup.exe)
 1) cd to windows\install
 2) Added c:\Program Files\NSIS to the path ( if not already there )
 3) run makensis xensetup.nsi to create the xensetup.exe


C) Installing the package on the target VT box
1) Backup the guest image
2) Copy and the xensetup.exe to the target VT box and run it
3) Select "yes" to boot from SCSI
4) Reboot
5) To verify once rebooted, run devmgmt.msc. Under disk drives, you should see something like "PV SCSI Disk". Also, you should see XenSource Scsi Host Adapter, XenSource Ethernet Adapter, XenSource PCI to Xenbus bridge. Additionally, if you run services.msc, you should see XenSource WinGuest Service.


Known issues
-------------

