;
; xensetup.nsi
;


;--------------------------------
!include "MUI.nsh"
!include "LogicLib.nsh"
!include "StrFunc.nsh"
!include "FileFunc.nsh"
!include "winver.nsh"
!include "drvsetup.nsh"
!include "library.nsh"
!include "TextLog.nsh"

# Declare used functions
${StrTok}
${UnStrTok}
${StrStr}

!define REG_UNINSTALL "Software\Microsoft\Windows\CurrentVersion\Uninstall\Citrix XenTools"
!define REG_XENTOOLS_PATH "SOFTWARE\Citrix\XenTools"

!define OLD_REG_UNINSTALL "Software\Microsoft\Windows\CurrentVersion\Uninstall\XenSource"
!define OLD_REG_XENTOOLS_PATH "SOFTWARE\Xensource"

!define REG_IDECDDB_PATH "SYSTEM\CurrentControlSet\Control\CriticalDeviceDatabase\pci#VEN_8086&CC_0101"
!define REG_XENVBDCDDB_PATH "SYSTEM\CurrentControlSet\Control\CriticalDeviceDatabase\pci#VEN_5853&dev_0001&subsys_00015853"

!define BUILD_PREFIX "..\build\i386"
!define BUILD_PREFIX64 "..\build\amd64"
!define SIGN_PREFIX "..\sign32"
!define SIGN_PREFIX_64 "..\sign64"

# OsType is one of 8Plus, 2008r2, 7, 2008, Vista, 2003, XP, and 2000.
Var /GLOBAL OsType
Var /GLOBAL ServicePack

# yes if the host is amd64, no if it's x86.  Note that
# %PROCESSOR_ARCHITECTURE% won't give the right value, since the
# installer is 32 bit anyway.
Var /GLOBAL IsAmd64

# yes if we're installing on a native Windows, probably as a first step
# of a P2V.
Var /GLOBAL IsNativeWindows
Var /GLOBAL ServicesPipeTimeout
Var /GLOBAL InitialServicesPipeTimeout

#
Var /GLOBAL SystemStartOptions
Var /GLOBAL MiniNT
Var /GLOBAL EnableFullCrashDump

; Branding and version information
; Branding and version information
!ifndef VERMAJOR
!define CurrentMajorVersion 14
!else
!define CurrentMajorVersion ${VERMAJOR}
!endif

!ifndef VERMINOR
!define CurrentMinorVersion 0
!else
!define CurrentMinorVersion ${VERMINOR}
!endif

!ifndef VERMICRO
!define CurrentMicroVersion 0
!else
!define CurrentMicroVersion ${VERMICRO}
!endif

!ifndef VERBUILD
!define CurrentBuildVersion 0
!else
!define CurrentBuildVersion ${VERBUILD}
!endif

!define ProductName "OpenXT Tools for Virtual Machines"
!define CompanyName "OpenXT"
!define LegalCopyright "Empty"

!define UrlAbout "http://www.openxt.org"
!define UrlUpdate "http://www.openxt.org"

!define FileDescription "Installer"

# What are we upgrading from?  0 if we're not upgrading.
Var /GLOBAL UpgradingFromMajor
Var /GLOBAL UpgradingFromMinor
Var /GLOBAL UpgradingFromMicro
Var /GLOBAL UpgradingFromBuild

# Where was the thing we're upgrading from installed? "" if we're not
# upgrading
Var /GLOBAL UpgradingFromPath

Var /GLOBAL REALSYSDIR

; Execution level
RequestExecutionLevel admin

; Branding text on the installer
BrandingText "${ProductName} ${CurrentMajorVersion}.${CurrentMinorVersion}.${CurrentMicroVersion}"

!define MUI_ICON "..\media\xen.ico"
!define MUI_UNICON "..\media\xen.ico"
!define MUI_WELCOMEFINISHPAGE_BITMAP "DialogInstall.bmp"
!define MUI_UNWELCOMEFINISHPAGE_BITMAP "DialogInstall.bmp"

!macro BackupFile FILE_DIR FILE BACKUP_TO
 IfFileExists "${BACKUP_TO}\*.*" +2
  CreateDirectory "${BACKUP_TO}"
 IfFileExists "${FILE_DIR}${FILE}" 0 +2
  CopyFiles /SILENT "${FILE_DIR}${FILE}" "${BACKUP_TO}"
!macroend

!macro RestoreFile BUP_DIR FILE RESTORE_TO
 IfFileExists "${BUP_DIR}\${FILE}" 0 +2
  CopyFiles "${BUP_DIR}\${FILE}" "${RESTORE_TO}"
!macroend

; The name of the installer
Name "${ProductName}"

;Version info
VIAddVersionKey "ProductName" "${ProductName}"
VIAddVersionKey "CompanyName" "${CompanyName}"
VIAddVersionKey "FileDescription" "${FileDescription}"
VIAddVersionKey "LegalCopyright" "${LegalCopyright}"
VIAddVersionKey "FileVersion" "${CurrentMajorVersion}.${CurrentMinorVersion}.${CurrentMicroVersion}.${CurrentBuildVersion}"
VIProductVersion "${CurrentMajorVersion}.${CurrentMinorVersion}.${CurrentMicroVersion}.${CurrentBuildVersion}"

; The file to write
OutFile "xensetup.exe"

; The default installation directory
InstallDir $PROGRAMFILES\Citrix\XenTools

##################################
# Pages
##################################
  !define MUI_LICENSEPAGE_CHECKBOX
  !insertmacro MUI_PAGE_LICENSE "license.txt"
  !insertmacro MUI_PAGE_DIRECTORY
  !insertmacro MUI_PAGE_INSTFILES
  !insertmacro MUI_PAGE_FINISH
  
  !insertmacro MUI_UNPAGE_CONFIRM
  !insertmacro MUI_UNPAGE_INSTFILES
  !insertmacro MUI_UNPAGE_FINISH

  !insertmacro MUI_LANGUAGE "English"

;Page directory
;Page instfiles

Function .onInit
System::Call 'kernel32::CreateMutexA(i 0, i 0, t "$(^Name)") i .r1 ?e'
 Pop $R0
 
 StrCmp $R0 0 +3
   MessageBox MB_OK|MB_ICONEXCLAMATION "There is already an instance of the ${ProductName} installer running."
   Abort
FunctionEnd

Var /GLOBAL PciDeviceName
Var /GLOBAL VesaDeviceName
Var /GLOBAL cmdLineParams

!insertmacro GetParameters
!insertmacro GetOptions
!insertmacro un.GetParameters
!insertmacro un.GetOptions

Function DeleteOemInf
Pop $0
FindFirst $3 $2 "$SYSDIR\pnputil.exe"
StrCmp $2 "" no_pnputil

DetailPrint "Removing $0 from DriverStore"
ExecWait '"$SYSDIR\pnputil.exe" "-f" "-d" "$0"'
Goto done

no_pnputil:
${LogText} "No pnputil"
Delete $WINDIR\inf\$0
${StrTok} $1 $0 "." "0" "1"
Delete "$WINDIR\inf\$1.pnf"

done:
FindClose $3
FunctionEnd

Function un.DeleteOemInf
Pop $0
FindFirst $3 $2 "$SYSDIR\pnputil.exe"
StrCmp $2 "" no_pnputil

DetailPrint "Removing $0 from DriverStore"
ExecWait '"$SYSDIR\pnputil.exe" "-f" "-d" "$0"'
Goto done

no_pnputil:
${UnLogText} "No pnputil"
Delete /REBOOTOK $WINDIR\inf\$0
${UnStrTok} $1 $0 "." "0" "1"
Delete /REBOOTOK "$WINDIR\inf\$1.pnf"

done:
FindClose $3
FunctionEnd

!macro DualUseFunctions_ un_

##################################
# DeleteInstalledOemInf() function
##################################
Function ${un_}DeleteInstalledOemInf
Exch $0 # search for hwid eg "Xen\vif"
StrCpy $1 $0
FindFirst $5 $6 "$WINDIR\inf\oem*.inf"

again:
StrCmp $6 "" done

Push $WINDIR\inf\$6 # file to search
Push $1 # search text
Call ${un_}FileSearch
Pop $2 #Number of times found throughout
Pop $3 #Found at all? yes/no
Pop $4 #Number of lines found in

StrCmp $3 "yes" 0 next

Push $6
Call ${un_}DeleteOemInf

next:
FindNext $5 $6
Goto again

done:
FindClose $5
Exch $6
FunctionEnd

##################################
# FileSearch() function
# cut & paste from nsis website
##################################
Function ${un_}FileSearch
Exch $0 ;search for
Exch
Exch $1 ;input file
Push $2
Push $3
Push $4
Push $5
Push $6
Push $7
Push $8
Push $9
Push $R0
  FileOpen $2 $1 r
  StrLen $4 $0
  StrCpy $5 0
  StrCpy $7 no
  StrCpy $8 0
  StrCpy $9 0
  ClearErrors
loop_main:
  FileRead $2 $3
  IfErrors done
 IntOp $R0 $R0 + $9
  StrCpy $9 0
  StrCpy $5 0
filter_top:
 IntOp $5 $5 - 1
  StrCpy $6 $3 $4 $5
  StrCmp $6 "" loop_main
  StrCmp $6 $0 0 filter_top
  StrCpy $3 $3 $5
  StrCpy $5 0
 StrCpy $7 yes
 StrCpy $9 1
 IntOp $8 $8 + 1
Goto filter_top
done:
  FileClose $2
  StrCpy $0 $8
  StrCpy $1 $7
  StrCpy $2 $R0
Pop $R0
Pop $9
Pop $8
Pop $7
Pop $6
Pop $5
Pop $4
Pop $3
Exch $2 ;output number of lines
Exch 2
Exch $1 ;output yes/no
Exch
Exch $0 ;output count found
FunctionEnd

!macroend

##################################
# PreInstallCheck() function
##################################
Function PreInstallCheck
Push $R0
Push $R1
Push $R2
StrCpy $R0 "pass"
Call GetWindowsVersion
Pop $R2
Pop $R1
StrCpy $OsType $R1
StrCpy $ServicePack $R2
DetailPrint "Windows version detected - $OsType, Service Pack - $ServicePack"
${LogText} "Windows version detected - $OsType, Service Pack - $ServicePack"

${If} "$OsType" == "XP"
   ${If} "$ServicePack" < 2
      Goto version_mismatch
   ${EndIf}
${ElseIf} "$OsType" == "2000"
   ${If} "$ServicePack" < 4
      Goto version_mismatch
   ${EndIf}
${EndIf}

Goto next_check

version_mismatch:
StrCmp $ServicePack "" no_servicepack
StrCpy $R3 "$OsType (SP$ServicePack)"
Goto printMessage
no_servicepack:
StrCpy $R3 $OsType

printMessage:
MessageBox MB_YESNO|MB_ICONQUESTION "You are running Windows $R3.  Only Windows Server 2003 (all service packs), Windows XP (SP2 onwards), and Windows 2000 (SP4 onwards) are supported. Do you want to continue?" /SD IDYES IDNO stop
Goto next_check

next_check:

# What kind of processor do we have?
System::Call 'install::IsAmd64() i.r0'
${If} $0 = 1
   StrCpy $IsAmd64 "yes"
${Else}
   StrCpy $IsAmd64 "no"
${EndIf}

Strcpy $IsNativeWindows "no"

# The function we want to call doesn't have a real name, so
# call by ordinal.
System::Call "kernel32::GetModuleHandle(t 'shell32.dll') i .s"
System::Call "kernel32::GetProcAddress(i s, i 680) i .r0"
System::Call "::$0() i .r0"
IntCmp "$0" 1 0 notadmin

StrCpy $PciDeviceName "PCI\VEN_5853&DEV_0001&SUBSYS_00015853"
System::Call '${myFindExistingDevice}?e ("$PciDeviceName") .r0'
Pop $1 ; last error
DetailPrint "pci device detected - $0 $1"
IntCmp $0 1 done_do_vesa

StrCpy $PciDeviceName "PCI\VEN_5853&DEV_0001"
System::Call '${myFindExistingDevice}?e ("$PciDeviceName") .r0'
Pop $1 ; last error
DetailPrint "pci device detected - $0 $1"
IntCmp $0 1 done_do_vesa dev_notfound

    MessageBox MB_OK 'Unable to find/load FindExistingDevice() in install.dll'
    Strcpy $R0 'fail'
    Goto done

done_do_vesa:

StrCpy $VesaDeviceName "PCI\VEN_1234&DEV_1111&SUBSYS_00015853"
System::Call '${myFindExistingDevice}?e ("$VesaDeviceName") .r0'
Pop $1 ; last error
DetailPrint "vesa device detected - $0 $1"
IntCmp $0 1 done

StrCpy $VesaDeviceName "PCI\VEN_1234&DEV_1111"
System::Call '${myFindExistingDevice}?e ("$VesaDeviceName") .r0'
Pop $1 ; last error
DetailPrint "vesa device detected - $0 $1"
IntCmp $0 1 done dev_notfound

    MessageBox MB_OK 'Unable to find/load FindExistingDevice() in install.dll'
    Strcpy $R0 'fail'
    Goto done

dev_notfound:
    Strcpy $IsNativeWindows "yes"
    MessageBox MB_YESNO|MB_ICONQUESTION "Unable to detect a valid platform. Do you still want to continue?" /SD IDYES IDYES done
    Strcpy $R0 'fail'
    Goto done

notadmin:
    MessageBox MB_OK "You must be an administrator to install ${ProductName}"
    Strcpy $R0 'fail'
    Goto done

stop:
    Strcpy $R0 'fail'
    Goto done

done:
Pop $R2
Pop $R1
Exch $R0
FunctionEnd

##################################
# Video Acceleration.Level() function
##################################
Function "VideoAccelerationLevel"
  Var /GLOBAL VideoPrefix
  Var /GLOBAL ServiceValue
  Var /GLOBAL VidGuid

  StrCpy $VideoPrefix "System\CurrentControlSet\CONTROL\VIDEO"
  StrCpy $0 0
  
  find_cirrus_loop:
    EnumRegKey $VidGuid HKLM $VideoPrefix $0
    StrCmp $VidGuid "" done_error_cirrus
    IntOp $0 $0 + 1
    StrCpy $ServiceValue "$VideoPrefix\$VidGuid\Video"
    ReadRegStr $1 HKLM $ServiceValue Service
    StrCmp $1 "cirrus" found_cirrus
    goto find_cirrus_loop
    
  found_cirrus:

    StrCmp $VidGuid "" done_error_cirrus

    ${LogText} "Disabling video acceleration: HKLM\$VideoPrefix\$VidGuid\0000\Acceleration.Level=5"
    WriteRegDWORD HKLM "$VideoPrefix\$VidGuid\0000" "Acceleration.Level" 0x00000005

  done_find_cirrus:
  Return

  done_error_cirrus:
    ${LogText} "Unable to disable video acceleration. Couldnt find cirrus registry key."
    goto done_find_cirrus
  
FunctionEnd

####################
# Install section
####################
Section "Install Section" SecDrvInst ;No components page, name is not important
  CreateDirectory "$TEMP\Citrix"
  ${LogSetFileName} "$TEMP\Citrix\log_xensetup.txt"
  ${LogSetOn}
${If} "$OsType" != "8Plus"
  Call VideoAccelerationLevel
${Endif} 
  # Always use 32 bit install.dll, since the installer is a 32 bit
  # application.
  SetOutPath $TEMP
  File "${BUILD_PREFIX}\install.dll"

  ${LogText} "Preinstall checks..."
  DetailPrint "Preinstall checks..."

  Call PreInstallCheck
  Pop $R2
  Delete /REBOOTOK $TEMP\install.dll
  StrCmp $R2 "fail" done
  
  ${GetParameters} $cmdLineParams

  # Asked to do an uninstall?
  ${GetOptions} $cmdLineParams '/uninstall' $R0
  IfErrors +1 uninstall_block

  StrCpy $UpgradingFromMajor "0"
  StrCpy $UpgradingFromMinor "0"
  StrCpy $UpgradingFromMicro "0"
  StrCpy $UpgradingFromBuild "0"

  # check if first install or update
  ClearErrors      
  ReadRegStr $UpgradingFromPath HKLM ${REG_XENTOOLS_PATH} "Install_Dir"
  ${If} ${Errors}
    # See if we are upgrading over an older (pre 4.1) product
    ReadRegStr $UpgradingFromPath HKLM ${OLD_REG_XENTOOLS_PATH} "Install_Dir"
    ${If} ${Errors}
      # New installation
      ${LogText} "New installation detected!"
      DetailPrint "New installation detected!"
      StrCpy $R0 "New" # new installation
      StrCpy $UpgradingFromPath ""
    ${Else}
      # updating over old (pre 4.1) installation
      ${LogText} "Update installation detected!"
      DetailPrint "Update installation detected!"
      
      # Check the version of the installed tools package
      ClearErrors
      ReadRegDWORD $UpgradingFromMajor HKLM ${OLD_REG_XENTOOLS_PATH} "MajorVersion"
      ReadRegDWORD $UpgradingFromMinor HKLM ${OLD_REG_XENTOOLS_PATH} "MinorVersion"
      IfErrors upgrade_from_corrupt

      ClearErrors
      ReadRegDWORD $UpgradingFromBuild HKLM ${OLD_REG_XENTOOLS_PATH} "BuildVersion"
      ${If} ${Errors}
        StrCpy $UpgradingFromBuild "0"
      ${EndIf}

      # Hack: Miami beta1 claimed to be version 4.1, when it should have
      # been 4.0.94.  Fix it up based on the build number.
      ${If} $UpgradingFromBuild = 6010
        StrCpy $UpgradingFromMajor "4"
        StrCpy $UpgradingFromMinor "0"
        StrCpy $UpgradingFromMicro "94"
      ${EndIf}
    ${EndIf}
  ${Else}
    # updating over 4.1 or newer installation
    ${LogText} "Update installation detected!"
    DetailPrint "Update installation detected!"

    # Check the version of the installed tools package
    ClearErrors
    ReadRegDWORD $UpgradingFromMajor HKLM ${REG_XENTOOLS_PATH} "MajorVersion"
    ReadRegDWORD $UpgradingFromMinor HKLM ${REG_XENTOOLS_PATH} "MinorVersion"
    ReadRegDWORD $UpgradingFromBuild HKLM ${REG_XENTOOLS_PATH} "BuildVersion"
    IfErrors upgrade_from_corrupt

    # Old versions didn't include a micro version.  Assume 0 if it's
    # unavailable.
    ClearErrors
    ReadRegDWORD $UpgradingFromMicro HKLM ${REG_XENTOOLS_PATH} "MicroVersion"
    ${If} ${Errors}
      StrCpy $UpgradingFromMicro "0"
    ${EndIf}
  ${EndIf}

  ${If} $R0 != "New"
    # Is the version currently installed older or newer than the current one?
    ${If} ${CurrentMajorVersion} < $UpgradingFromMajor
      StrCpy $5 "lesser"
    ${ElseIf} ${CurrentMajorVersion} = $UpgradingFromMajor
      ${If} ${CurrentMinorVersion} < $UpgradingFromMinor
        StrCpy $5 "lesser"
      ${ElseIf} ${CurrentMinorVersion} = $UpgradingFromMinor
        ${If} ${CurrentMicroVersion} < $UpgradingFromMicro
          StrCpy $5 "lesser"
        ${ElseIf} ${CurrentMicroVersion} = $UpgradingFromMicro
          ${If} ${CurrentBuildVersion} < $UpgradingFromBuild
            StrCpy $5 "lesser"
          ${Else}
            StrCpy $5 "greater"
          ${EndIf}
        ${Else}
          StrCpy $5 "greater"
        ${EndIf}
      ${Else}
        StrCpy $5 "greater"
      ${EndIf}
    ${Else}
      StrCpy $5 "greater"
    ${EndIf}

    ${If} $5 == "lesser"
      MessageBox MB_YESNO|MB_ICONQUESTION "The version of the ${ProductName} you are installing is older than the current installed version.  Continue installation?" /SD IDYES IDNO done 
    ${EndIf}

    StrCpy $R0 "Update" # update installation

  ${EndIf}

  File "${BUILD_PREFIX}\uninst_pending.exe"
  ExecWait '"$TEMP\uninst_pending.exe"' $0
  ${If} ${Errors}
  ${OrIf} "$0" != "0"
    Delete "$TEMP\uninst_pending.exe"
    MessageBox MB_OK "${ProductName} are already installed, but an uninstallation is pending.  You must complete the uninstallation before attempting to reinstall the tools."
    Goto done
  ${EndIf}
  Delete "$TEMP\uninst_pending.exe"

  WriteRegDWORD HKLM ${REG_XENTOOLS_PATH} "MajorVersion" ${CurrentMajorVersion}
  WriteRegDWORD HKLM ${REG_XENTOOLS_PATH} "MinorVersion" ${CurrentMinorVersion}
  WriteRegDWORD HKLM ${REG_XENTOOLS_PATH} "MicroVersion" ${CurrentMicroVersion}
  WriteRegDWORD HKLM ${REG_XENTOOLS_PATH} "BuildVersion" ${CurrentBuildVersion}
  WriteRegStr   HKLM ${REG_XENTOOLS_PATH} "Install_Dir" "$INSTDIR" 
  
  #
  # Did the caller indicate we need to enable full crash dump files? If so, we
  # also make sure crash dumps are enabled and where they need to be written.
  #  
  ClearErrors
  ${GetOptions} $cmdLineParams '/fulldump' $EnableFullCrashDump
  ${If} ${Errors}
  ${Else}
      ${LogText} "Adding registry entries to create full dump files..."
      DetailPrint "Adding registry entries to create full dump files..."
      WriteRegDWORD HKLM "SYSTEM\CurrentControlSet\Control\CrashControl" "CrashDumpEnabled" 1
      WriteRegDWORD HKLM "SYSTEM\CurrentControlSet\Control\CrashControl" "Overwrite" 1
      WriteRegDWORD HKLM "SYSTEM\CurrentControlSet\Control\CrashControl" "LogEvent" 1
      WriteRegStr HKLM "SYSTEM\CurrentControlSet\Control\CrashControl" "DumpFile" "C:\WINDOWS\MEMORY.DMP"
  ${EndIf}

  ${LogText} "Copying files to $INSTDIR..."
  
  SetOutPath $INSTDIR

# Driver files once signed cannot be changed in any way, including renaming them.  If you do this, Windows 7 will reject the driver on boot leading
# to blue screens on the boot drivers
  ${If} "$IsAmd64" == "no"

    File ${SIGN_PREFIX}\xenvusb.sys

    File /nonfatal ${SIGN_PREFIX}\xenvusb.cat
    File ${SIGN_PREFIX}\xenvusb.inf
    File ${SIGN_PREFIX}\WdfCoInstaller01009.dll

    File ${SIGN_PREFIX}\xevtchn.sys
    File ${SIGN_PREFIX}\xevtchn.inf
    File /nonfatal ${SIGN_PREFIX}\xevtchn.cat

    File ${SIGN_PREFIX}\xenvbd.sys
    File ${SIGN_PREFIX}\scsifilt.sys
    File /nonfatal ${SIGN_PREFIX}\xenvbd.cat
    File ${SIGN_PREFIX}\xenvbd.inf

    File ${SIGN_PREFIX}\xennet.sys
    File ${SIGN_PREFIX}\xennet6.sys
    File ${SIGN_PREFIX}\xenwnet.sys
    File ${SIGN_PREFIX}\xenwnet6.sys
    File ${SIGN_PREFIX}\xennet.inf
    File /nonfatal ${SIGN_PREFIX}\xennet.cat
    File ${SIGN_PREFIX}\xenwnet.inf
    File /nonfatal ${SIGN_PREFIX}\xenwnet.cat
	File /nonfatal ${SIGN_PREFIX}\xenaud.cat
	File ${SIGN_PREFIX}\xenaud.sys
	File ${SIGN_PREFIX}\xenaud.inf

!ifdef INSTALL_XENVESA
${If}  "$OsType" != "8Plus"
    File ${SIGN_PREFIX}\xenvesa-miniport.sys
    File ${SIGN_PREFIX}\xenvesa-display.dll

    ${If} "$OsType" == "XP"
        File ${SIGN_PREFIX}\xenvesa-xp.inf
        File /nonfatal ${SIGN_PREFIX}\xenvesa-xp.cat
    ${Else} 
        File ${SIGN_PREFIX}\xenvesa-lh.inf
        File /nonfatal ${SIGN_PREFIX}\xenvesa-lh.cat
    ${EndIf}
${EndIf}
!endif

    File ${BUILD_PREFIX}\xeninp.sys
    File /nonfatal ${SIGN_PREFIX}\xeninp.cat
    File ${SIGN_PREFIX}\xeninp.inf

    ${If} "$OsType" != "2000"
      File ${SIGN_PREFIX}\xenv4v.sys
      File /nonfatal ${SIGN_PREFIX}\xenv4v.cat
      File ${SIGN_PREFIX}\xenv4v.inf
    ${EndIf}

    File ${SIGN_PREFIX}\xenutil.sys

    File /oname=xs.new ${BUILD_PREFIX}\xs.dll
    Rename /REBOOTOK xs.new xs.dll
!ifndef NO_INSTALL_XENSERVICE
    File /oname=xenservice.new ${BUILD_PREFIX}\xenservice.exe
    Rename /REBOOTOK xenservice.new xenservice.exe
!endif
    File /oname=xsutil.new ${BUILD_PREFIX}\xsutil.dll
    Rename /REBOOTOK xsutil.new xsutil.dll
    File /oname=xs2.new ${BUILD_PREFIX}\xs2.dll
    Rename /REBOOTOK xs2.new xs2.dll

    File ${BUILD_PREFIX}\removedev.exe
    File ${BUILD_PREFIX}\sync.exe
    File ${BUILD_PREFIX}\xenstore_client.exe
    File ${BUILD_PREFIX}\enableuninst.exe
    File ${BUILD_PREFIX}\getlogs.exe
    File ${BUILD_PREFIX}\query_balloon.exe
    File ${BUILD_PREFIX}\copyvif.exe
    File ${BUILD_PREFIX}\fixdiskfilters.exe

	File ${BUILD_PREFIX}\OxtService.exe
	File ${BUILD_PREFIX}\OxtUserAgent.exe

	; this is the 64bit definition DO NOT RENAME THE FILES
  ${Else}
    File ${SIGN_PREFIX_64}\xenvusb.sys

    File /nonfatal ${SIGN_PREFIX_64}\xenvusb.cat
    File ${SIGN_PREFIX_64}\xenvusb.inf
    File ${SIGN_PREFIX_64}\WdfCoInstaller01009.dll
	
    File ${SIGN_PREFIX_64}\xevtchn.sys
    File ${SIGN_PREFIX_64}\xevtchn.inf 
    File /nonfatal ${SIGN_PREFIX_64}\xevtchn.cat

    File ${SIGN_PREFIX_64}\xenvbd.sys
    File ${SIGN_PREFIX_64}\scsifilt.sys
    File ${SIGN_PREFIX_64}\xenvbd.inf
    File /nonfatal ${SIGN_PREFIX_64}\xenvbd.cat

    File ${SIGN_PREFIX_64}\xennet.sys
    File ${SIGN_PREFIX_64}\xennet6.sys
    File ${SIGN_PREFIX_64}\xenwnet.sys
    File ${SIGN_PREFIX_64}\xenwnet6.sys
    File ${SIGN_PREFIX_64}\xennet.inf
    File /nonfatal ${SIGN_PREFIX_64}\xennet.cat
    File ${SIGN_PREFIX_64}\xenwnet.inf
    File /nonfatal ${SIGN_PREFIX_64}\xenwnet.cat
	File /nonfatal ${SIGN_PREFIX_64}\xenaud.cat
	File ${SIGN_PREFIX_64}\xenaud.sys
	File ${SIGN_PREFIX_64}\xenaud.inf
	
!ifdef INSTALL_XENVESA
${If} "$OsType" != "8Plus"
    File ${SIGN_PREFIX_64}\xenvesa-miniport.sys
    File ${SIGN_PREFIX_64}\xenvesa-display.dll

    ${If} "$OsType" == "XP"
        File ${SIGN_PREFIX_64}\xenvesa-xp.inf
        File /nonfatal ${SIGN_PREFIX_64}\xenvesa-xp.cat
    ${Else}
        File ${SIGN_PREFIX_64}\xenvesa-lh.inf
        File ${SIGN_PREFIX_64}\xenvesa-lh.cat
    ${EndIf}
${EndIf}
!endif

	File ${SIGN_PREFIX_64}\xeninp.sys
	File ${SIGN_PREFIX_64}\xeninp.cat
	File ${SIGN_PREFIX_64}\xeninp.inf

    ${If} "$OsType" != "2000"
      File ${SIGN_PREFIX_64}\xenv4v.sys
      File ${SIGN_PREFIX_64}\xenv4v.inf
      File /nonfatal ${SIGN_PREFIX_64}\xenv4v.cat
    ${EndIf}

    File ${SIGN_PREFIX_64}\xenutil.sys

    File /oname=xs.new ${BUILD_PREFIX64}\xs.dll
    Rename /REBOOTOK xs.new xs.dll
!ifndef NO_INSTALL_XENSERVICE
    File /oname=xenservice.new ${BUILD_PREFIX64}\xenservice.exe
    Rename /REBOOTOK xenservice.new xenservice.exe
!endif
    File /oname=xsutil.new ${BUILD_PREFIX64}\xsutil.dll
    Rename /REBOOTOK xsutil.new xsutil.dll

    File /oname=xs2.new ${BUILD_PREFIX64}\xs2.dll
    Rename /REBOOTOK xs2.new xs2.dll

    File /oname=xs2-32.new ${BUILD_PREFIX}\xs2.dll
    Rename /REBOOTOK xs2-32.new xs2_32.dll

    File ${BUILD_PREFIX64}\xenstore_client.exe
    File ${BUILD_PREFIX64}\removedev.exe
    File ${BUILD_PREFIX64}\sync.exe
    File ${BUILD_PREFIX64}\enableuninst.exe
    File ${BUILD_PREFIX64}\getlogs.exe
    File ${BUILD_PREFIX64}\query_balloon.exe
    File ${BUILD_PREFIX64}\copyvif.exe
    File ${BUILD_PREFIX64}\fixdiskfilters.exe

	File ${BUILD_PREFIX}\OxtService.exe
	File ${BUILD_PREFIX}\OxtUserAgent.exe

  ${EndIf}

  ${LogText} "File copy done."

  ${If} "$IsAmd64" == "yes"
    StrCpy "$1" "$INSTDIR\xs2.dll"
    System::Call "install::SetXSdllRegKey(t r1)"
    WriteRegStr HKLM Software\Citrix\XenTools "xs2.dll" $INSTDIR\xs2_32.dll  
  ${Else}
    WriteRegStr HKLM Software\Citrix\XenTools "xs2.dll" $INSTDIR\xs2.dll
  ${EndIf}

  ${If} $R0 == "New"
    DetailPrint "Copying ioemu network settings..."
    ExecWait '"$INSTDIR\copyvif.exe" "$INSTDIR\copyvif.log.txt"'
  ${EndIf}

  # Vista has a bug where unless you change the INF file version it won't update the drivers.
  # The easy work around is to simply delete any old Xen INFs in the %windir%\inf directory
  # prior to installing the new drivers.

  # RJP removing old rubbish code that deleted the INF files manually. This approach is
  # totally off the rails... New stuffs is from XenServer

  # Remove old drivers
  Push "PCI\VEN_5853&DEV_C110&SUBSYS_C1105853"
  Call DeleteInstalledOemInf

  Push "PCI\VEN_5853&DEV_C110"
  Call DeleteInstalledOemInf

  Push "XEN\VIF"
  Call DeleteInstalledOemInf

  Push "XEN\VWIF"
  Call DeleteInstalledOemInf

  Push "XEN\V4V"
  Call DeleteInstalledOemInf

  Push "XENBUS\CLASS&IFACE"
  Call DeleteInstalledOemInf

  Push "PCI\VEN_5853&DEV_0001&SUBSYS_00015853"
  Call DeleteInstalledOemInf

  Push "PCI\VEN_5853&DEV_0001"
  Call DeleteInstalledOemInf

  Push "ROOT\XENEVTCHN"
  Call DeleteInstalledOemInf

  Push "PCI\VEN_1234&DEV_1111&SUBSYS_00015853&REV_00"
  Call DeleteInstalledOemInf

  Push "PCI\VEN_1234&DEV_1111"
  Call DeleteInstalledOemInf

  Push "PCI\VEN_8086&DEV_2415&CC_0401"
  Call DeleteInstalledOemInf

  Push "PCI\VEN_8086&DEV_2415"
  Call DeleteInstalledOemInf

  Push "XEN\VUSB"
  Call DeleteInstalledOemInf
  
  Push "PCI\VEN_111d&DEV_76b2"
  Call DeleteInstalledOemInf
  
  # Install drivers
  SetOutPath $TEMP
  ${if} "$IsAmd64" == "yes"
    File ${BUILD_PREFIX64}\installdriver.exe
  ${else}
    File ${BUILD_PREFIX}\installdriver.exe
  ${endif}
  ClearErrors

  ReadRegStr $SystemStartOptions HKLM SYSTEM\CurrentControlSet\Control "SystemStartOptions"  
  DetailPrint "SystemStartOptions = $SystemStartOptions"
  Push $SystemStartOptions
  Push "/MININT"
  Call StrStr
  Pop $MiniNT  
  StrCmp $MiniNT "" NoPVBoot InstallINFs
  
NoPVBoot:  
  WriteRegDWORD HKLM "SYSTEM\CurrentControlSet\Services\xenevtchn" "NOPVBoot" 0x00000001
  
InstallINFs:
  ${LogText} "Installing INF files..."
  ExecWait '"$TEMP\installdriver.exe" "/i" "$HWNDPARENT" "$INSTDIR\xeninp.inf"' $0
  ExecWait '"$TEMP\installdriver.exe" "/i" "$HWNDPARENT" "$INSTDIR\xevtchn.inf"' $0
  ExecWait '"$TEMP\installdriver.exe" "/i" "$HWNDPARENT" "$INSTDIR\xenvbd.inf"' $0
  ExecWait '"$TEMP\installdriver.exe" "/i" "$HWNDPARENT" "$INSTDIR\xennet.inf"' $0
  ExecWait '"$TEMP\installdriver.exe" "/i" "$HWNDPARENT" "$INSTDIR\xenwnet.inf"' $0
  ExecWait '"$TEMP\installdriver.exe" "/i" "$HWNDPARENT" "$INSTDIR\xenaud.inf"' $0
  
!ifdef INSTALL_XENVESA
${If} "$OsType" == "XP"
  ExecWait '"$TEMP\installdriver.exe" "/i" "$HWNDPARENT" "$INSTDIR\xenvesa-xp.inf"' $0
${Else}
  ExecWait '"$TEMP\installdriver.exe" "/i" "$HWNDPARENT" "$INSTDIR\xenvesa-lh.inf"' $0
${EndIf}
!endif

  ; install vusb inf file for win7 or later
  ${If} "$OsType" == "7" 
  ${OrIf} "$OsType" == "8Plus"
    ExecWait '"$TEMP\installdriver.exe" "/i" "$HWNDPARENT" "$INSTDIR\xenvusb.inf"' $0
  ${EndIf}
	
  ${If} "$OsType" != "2000"
    ExecWait '"$TEMP\installdriver.exe" "/i" "$HWNDPARENT" "$INSTDIR\xenv4v.inf"' $0
  ${EndIf}

  ${LogText} "Installing xenmou drivers..."
  DetailPrint "Installing xenmou driver..."
    ${If} $R0 == "New"
      ExecWait '"$TEMP\installdriver.exe" "/p" "$HWNDPARENT" "PCI\VEN_5853&DEV_C110&SUBSYS_C1105853" "$INSTDIR\xeninp.inf" "0"' $0
    ${else}
      ExecWait '"$TEMP\installdriver.exe" "/p" "$HWNDPARENT" "PCI\VEN_5853&DEV_C110&SUBSYS_C1105853" "$INSTDIR\xeninp.inf" "1"' $0
    ${endif}
  IfErrors error
  IntCmp "$0" 0 0 error
  
  System::Call '${myFindExistingDevice}?e ("root\xenevtchn") .r0'
  ${If} $0 = 1
    ${LogText} "Upgrading xenbus root driver..."
    DetailPrint "Upgrading xenbus root driver..."
    ExecWait '"$TEMP\installdriver.exe" "/p" "$HWNDPARENT" "root\xenevtchn" "$INSTDIR\xevtchn.inf" "1"' $0
  ${else}
    ${LogText} "Installing xenbus root driver..."
    DetailPrint "Installing xenbus root driver..."
    ExecWait '"$TEMP\installdriver.exe" "/r" "$HWNDPARENT" "root\xenevtchn" "$INSTDIR\xevtchn.inf"' $0
  ${endif}
  
  ${If} "$OsType" == "7" 
  ${OrIf} "$OsType" == "8Plus"
    ${If} $R0 == "New"
      ExecWait '"$TEMP\installdriver.exe" "/p" "$HWNDPARENT" "XEN\vusb" "$INSTDIR\xenvusb.inf" "0"' $0
    ${else}
      ExecWait '"$TEMP\installdriver.exe" "/p" "$HWNDPARENT" "XEN\vusb" "$INSTDIR\xenvusb.inf" "1"' $0
    ${endif}
  ${endif}
  
  IfErrors error
  IntCmp "$0" 0 0 error

  # scsiport defaults to a stupidly small queue size.  Crank it up to the
  # maximum.  This will be ignored if we happen to be using storport, but
  # setting it is harmless.
  WriteRegDWORD HKLM "SYSTEM\CurrentControlSet\Services\xenvbd\parameters\Device0" "NumberOfRequests" 254

  ${LogText} "Installing xenvbd driver..."
  DetailPrint "Installing xenvbd driver..."
  ${If} $R0 == "New"
    ExecWait '"$TEMP\installdriver.exe" "/p" "$HWNDPARENT" "$PciDeviceName" "$INSTDIR\xenvbd.inf" "0"' $0
  ${else}
    ExecWait '"$TEMP\installdriver.exe" "/p" "$HWNDPARENT" "$PciDeviceName" "$INSTDIR\xenvbd.inf" "1"' $0
  ${endif}
  IfErrors error
  IntCmp "$0" 0 0 error

  ${LogText} "Installing xennet driver..."
  DetailPrint "Installing xennet driver..."
  ${If} $R0 == "New"
    ExecWait '"$TEMP\installdriver.exe" "/p" "$HWNDPARENT" "XEN\vif" "$INSTDIR\xennet.inf" "0"' $0
  ${else}
    ExecWait '"$TEMP\installdriver.exe" "/p" "$HWNDPARENT" "XEN\vif" "$INSTDIR\xennet.inf" "1"' $0
  ${endif}
  IfErrors error
  IntCmp "$0" 0 0 error
  
  ${LogText} "Installing xenwnet driver..."
  DetailPrint "Installing xenwnet driver..."
  ${If} $R0 == "New"
    ExecWait '"$TEMP\installdriver.exe" "/p" "$HWNDPARENT" "XEN\vwif" "$INSTDIR\xenwnet.inf" "0"' $0
  ${else}
    ExecWait '"$TEMP\installdriver.exe" "/p" "$HWNDPARENT" "XEN\vwif" "$INSTDIR\xenwnet.inf" "1"' $0
  ${endif}
  IfErrors error
  IntCmp "$0" 0 0 error

  # For now the PV driver installer is not installing xenvesa by default. Though it is installing it
  # correctly, we need the "phantom" driver instance for HDX mode in XenClient.
!ifdef INSTALL_XENVESA
  ${LogText} "Installing xenvesa driver..."
  DetailPrint "Installing xenvesa driver..."
  ${If} "$OsType" == "XP"
    ${If} $R0 == "New"
      ExecWait '"$TEMP\installdriver.exe" "/p" "$HWNDPARENT" "$VesaDeviceName" "$INSTDIR\xenvesa-xp.inf" "0"' $0
    ${else}
      ExecWait '"$TEMP\installdriver.exe" "/p" "$HWNDPARENT" "$VesaDeviceName" "$INSTDIR\xenvesa-xp.inf" "1"' $0
    ${endif}
  ${Else}
    ${If} $R0 == "New"
      ExecWait '"$TEMP\installdriver.exe" "/p" "$HWNDPARENT" "$VesaDeviceName" "$INSTDIR\xenvesa-lh.inf" "0"' $0
    ${else}
      ExecWait '"$TEMP\installdriver.exe" "/p" "$HWNDPARENT" "$VesaDeviceName" "$INSTDIR\xenvesa-lh.inf" "1"' $0
    ${endif}
  ${EndIf}
  IfErrors error
  IntCmp "$0" 0 0 error
!else
  ${LogText} "Skipping xenvesa driver installation..."
!endif
  
  ${If} "$OsType" != "2000"
    ${LogText} "Installing xenv4v driver..."
    DetailPrint "Installing xenv4v driver..."
    ${If} $R0 == "New"
      ExecWait '"$TEMP\installdriver.exe" "/p" "$HWNDPARENT" "XEN\v4v" "$INSTDIR\xenv4v.inf" "0"' $0
    ${else}
      ExecWait '"$TEMP\installdriver.exe" "/p" "$HWNDPARENT" "XEN\v4v" "$INSTDIR\xenv4v.inf" "1"' $0
    ${endif}
    IfErrors error
    IntCmp "$0" 0 0 error
    IntCmp "$0" 0 0 error
  ${EndIf}
  
  ${If} $IsNativeWindows == "yes"
    # Preinstall our disk drivers.  This is used when our drivers are installed in a non Xen
    # environment, like on real hardware, so our disk driver can be used on the initial boot.
    ExecWait '"$TEMP\installdriver.exe" "/d" "$HWNDPARENT" "$INSTDIR\xenvbd.inf" "xenvbd_inst" "xenvbd_inst.services"' $0
    WriteRegStr HKLM ${REG_XENVBDCDDB_PATH} "Service" "xenvbd"
    WriteRegStr HKLM ${REG_XENVBDCDDB_PATH} "ClassGUID" "{4D36E97B-E325-11CE-BFC1-08002BE10318}"
  ${endif}

  # Check if the ServicesPipeTimeout is set for the machine
  ReadRegDWORD $InitialServicesPipeTimeout HKLM "SYSTEM\CurrentControlSet\Control" "ServicesPipeTimeout"
  IfErrors ChangeServicesPipeTimeout

  # Save the initial timeout somewhere
  WriteRegDWORD HKLM "SOFTWARE\Citrix\XenTools" "ServicesPipeTimeout" $InitialServicesPipeTimeout

  # Now check if the timeout presently set is less than 120 seconds
  ${If} "$InitialServicesPipeTimeout" < 120000
        goto ChangeServicesPipeTimeout
  ${else}
        goto DoneCheckingServicesTimeout
  ${endif}

ChangeServicesPipeTimeout:
  WriteRegDWORD HKLM "SYSTEM\CurrentControlSet\Control" "ServicesPipeTimeout" 120000

DoneCheckingServicesTimeout:
!ifndef NO_INSTALL_XENSERVICE
  ${LogText} "Installing xenservice service..."
  ExecWait '"$TEMP\installdriver.exe" "/s" "$HWNDPARENT" \""$INSTDIR\xenservice.exe"\"' $0
  IfErrors error
  IntCmp "$0" 0 0 error
!endif

  ${LogText} "Installing OxtService service and OxtUserAgent..."
  ExecWait '"$INSTDIR\OxtService.exe" /Service' $0
  ExecWait '"$INSTDIR\OxtService.exe" /DenyRemoteAccess' $0
  WriteRegStr HKLM "SOFTWARE\Microsoft\Windows\CurrentVersion\Run" "OxtUserAgent" "$INSTDIR\OxtUserAgent.exe"

  ${LogText} "Drivers/service installation done."
  DetailPrint "Drivers/service installation done."

  ${LogText} "Verifying order of disk filter drivers..."
  ExecWait '"$INSTDIR\FixDiskFilters.exe"'
  
  ${LogText} "Generating uninstaller.exe..."
  DetailPrint "Generating uninstaller.exe..."

  writeUninstaller $INSTDIR\uninstaller.exe
  
  DeleteRegKey HKLM "${OLD_REG_UNINSTALL}"

  # Not adding ourself to Add/Remove programs
  #WriteRegStr HKLM "${REG_UNINSTALL}" "DisplayVersion" ${CurrentMajorVersion}.${CurrentMinorVersion}.${CurrentBuildVersion}
  #WriteRegStr HKLM "${REG_UNINSTALL}" "DisplayName" "${ProductName}"
  #WriteRegStr HKLM "${REG_UNINSTALL}" "Publisher" "${CompanyName}"
  #WriteRegStr HKLM "${REG_UNINSTALL}" "DisplayIcon" "$INSTDIR\uninstaller.exe,0"
  #WriteRegStr HKLM "${REG_UNINSTALL}" "UninstallString" "$INSTDIR\uninstaller.exe /cxmi"
  #WriteRegDWord HKLM "${REG_UNINSTALL}" "NoModify" 1
  #WriteRegDWord HKLM "${REG_UNINSTALL}" "NoRepair" 1
  #WriteRegStr HKLM "${REG_UNINSTALL}" "URLInfoAbout" "${UrlAbout}"
  #WriteRegStr HKLM "${REG_UNINSTALL}" "URLUpdateInfo" "${UrlUpdate}"
  
  #
  # Add a generic ide entry to the critical device database so that our image will VM
  # can load on other hypervisors.
  #
  WriteRegStr HKLM ${REG_IDECDDB_PATH} "Service" "intelide"
  WriteRegStr HKLM ${REG_IDECDDB_PATH} "ClassGUID" "{4D36E96A-E325-11CE-BFC1-08002BE10318}"

  ${If} $R0 != "New"
    # Pre XE 4.1 use to change the boot.ini to add a special PV entry.  If this is an upgrade
    # and we find a backed up boot.ini, then put it back since we no longer have PV entries.
    ${If} ${FileExists} "$UpgradingFromPath\nsi-backup\boot.ini"
      ReadRegStr $0 HKLM SOFTWARE\Microsoft\Windows\CurrentVersion\Setup "BootDir"
      Delete "$0boot.ini"
      !insertmacro RestoreFile "$UpgradingFromPath\nsi-backup" "boot.ini" "$0"  
    ${EndIf}
  
    ${If} $INSTDIR != $UpgradingFromPath
      #
      # The new installation is in a different place to the old one.
      # Clean up the old one.
      #
      Delete /REBOOTOK $UpgradingFromPath\xenstore_client.exe
      Delete /REBOOTOK $UpgradingFromPath\uninstaller.exe
      Delete /REBOOTOK $UpgradingFromPath\removedev.exe
      Delete /REBOOTOK $UpgradingFromPath\enableuninst.exe
      Delete /REBOOTOK $UpgradingFromPath\install.dll
      Delete /REBOOTOK $UpgradingFromPath\install.log
      Delete /REBOOTOK $UpgradingFromPath\sync.exe
      Delete /REBOOTOK $UpgradingFromPath\xennet.inf
      Delete /REBOOTOK $UpgradingFromPath\xennet.sys
      Delete /REBOOTOK $UpgradingFromPath\xennet6.sys
      Delete /REBOOTOK $UpgradingFromPath\xennet.cat
!ifndef NO_INSTALL_XENSERVICE
      Delete /REBOOTOK $UpgradingFromPath\xenservice.exe
!endif
      Delete /REBOOTOK $UpgradingFromPath\OxtService.exe
      Delete /REBOOTOK $UpgradingFromPath\OxtUserAgent.exe
      Delete /REBOOTOK $UpgradingFromPath\xenvbd.inf
      Delete /REBOOTOK $UpgradingFromPath\xenvbd.sys
      Delete /REBOOTOK $UpgradingFromPath\xenvbd.cat
      Delete /REBOOTOK $UpgradingFromPath\xevtchn.inf
      Delete /REBOOTOK $UpgradingFromPath\xevtchn.sys
      Delete /REBOOTOK $UpgradingFromPath\xevtchn.cat
      Delete /REBOOTOK $UpgradingFromPath\xenutil.sys
      Delete /REBOOTOK $UpgradingFromPath\xs.dll
      Delete /REBOOTOK $UpgradingFromPath\xsutil.dll      
      SetFileAttributes "$UpgradingFromPath\nsi-backup\boot.ini" NORMAL
      Delete /REBOOTOK $UpgradingFromPath\nsi-backup\boot.ini
      RMDir /REBOOTOK $UpgradingFromPath\nsi-backup
      RMDir /REBOOTOK $UpgradingFromPath
    ${EndIf}

    DeleteRegKey HKLM "${OLD_REG_XENTOOLS_PATH}"
  ${EndIf}
  
  # The default disk timeout of 10 seconds is a bit tight for us when
  # dom0 is heavily loaded.  It's basically never useful for the domU
  # to time out disk requests, so crank this up to two minutes.
  WriteRegDWORD HKLM "SYSTEM\CurrentControlSet\Services\Disk" "TimeOutValue" 120

  # Magic flag that is easy to read in WiX
  WriteRegDWORD HKLM ${REG_XENTOOLS_PATH} "Installed" 1

  SetRebootFlag true
  Goto done

upgrade_from_corrupt:
  MessageBox MB_OK "Existing installation is corrupt.  Remove it and try again."
  Goto done

error:
  MessageBox MB_OK "An error has been encountered during installation! Please check the install log for details."
  DeleteRegKey HKLM ${REG_XENTOOLS_PATH}

done:
  DeleteRegValue HKLM "SYSTEM\CurrentControlSet\Services\xenevtchn" "NOPVBoot"
  Delete "$TEMP\installdriver.exe"

# Work around NSIS bug: doesn't reboot if in silent mode.
  ${GetOptions} $cmdLineParams '/norestart' $R0
  IfErrors 0 end
  IfSilent 0 end
  IfRebootFlag 0 end
  ${LogText} "Rebooting."
  Reboot

  Goto end

uninstall_block:

  # Using installer to do the uninstall
  ExecWait '"$INSTDIR\uninstaller.exe" /S /norestart /internal'

end:
SectionEnd ; end the section


####################
# Uninstall section
####################
Section "Uninstall"

  ${UnLogSetFileName} "$TEMP\Citrix\log_un_xensetup.txt"
  ${UnLogSetOn}
  System::Call "kernel32::GetModuleHandle(t 'shell32.dll') i .s"
  System::Call "kernel32::GetProcAddress(i s, i 680) i .r0"
  System::Call "::$0() i .r0"
  ${If} "$0" <> 1
    MessageBox MB_OK "You must be an administrator to uninstall ${ProductName}."
    goto end_uninstall
  ${EndIf}
  
  SetOutPath $INSTDIR
  #This is busted, don't know if we really need it since uninstalling over RDP seems to work fine
  System::Call "xsutil::xs_is_physical_session() i.r0"
  ${If} "$0" == 0
    MessageBox MB_YESNO|MB_ICONEXCLAMATION "You appear to be accessing this system over RDP.  Uninstalling the network drivers may interfere with RDP sessions.  It is recommended that you abort this uninstaller and try again on the VGA console.  Continue installation?" IDNO end_uninstall
  ${EndIf}

  #Set uninstallation flag for UI
  ExecWait 'rundll32.exe xsutil.dll,xs_uninstalling'

  ${un.GetParameters} $cmdLineParams
  ${un.GetOptions} $cmdLineParams '/internal' $R0
  IfErrors +1 okUninstall
  ${UnLogText} "Uninstall failed, must be called internally from the installer!"
  Goto end_uninstall 
  okUninstall:
  ${UnLogText} "Uninstalling..."
  # Remove scsifilt
  ExecWait '"rundll32.exe" "setupapi.dll,InstallHinfSection uninstall 128 $INSTDIR\xenvbd.inf"'

  # If something has been stored, then handle it else remove key and exit.
  ReadRegDWORD $InitialServicesPipeTimeout HKLM "SOFTWARE\Citrix\XenTools" "ServicesPipeTimeout"
  IfErrors RemoveTimeoutKey
  
  # If the services timeout is still what we set it to, then reset the value to the initial value
  ReadRegDWORD $ServicesPipeTimeout HKLM "SYSTEM\CurrentControlSet\Control" "ServicesPipeTimeout"
  ${If} "$ServicesPipeTimeout" != 120000
   Goto SkipResettingServicesTimeout
  ${endif}

  WriteRegDWORD HKLM "SYSTEM\CurrentControlSet\Control" "ServicesPipeTimeout" $InitialServicesPipeTimeout
  DeleteRegValue HKLM "SOFTWARE\Citrix\XenTools" "ServicesPipeTimeout"
  Goto SkipResettingServicesTimeout
  
RemoveTimeoutKey:
  DeleteRegValue HKLM "SYSTEM\CurrentControlSet\Control" "ServicesPipeTimeout"

SkipResettingServicesTimeout:
!ifndef NO_INSTALL_XENSERVICE
  # stop and uninstall the xenservice
  ExecWait '"$INSTDIR\xenservice.exe" "-u"' $0
  DeleteRegKey HKLM SYSTEM\CurrentControlSet\Services\EventLog\Application\xensvc
!endif

  ExecWait '"$INSTDIR\OxtService.exe" /UnregServer' $0
  DeleteRegKey HKLM "SOFTWARE\Microsoft\Windows\CurrentVersion\Run\OxtUserAgent"

  # Make sure that the devices can be disabled.
  ExecWait '"$INSTDIR\enableuninst.exe"'

providerNotInstalled:  
  # Get the real system directory.  This is needed to delete files on x64
  System::Call "kernel32::Wow64DisableWow64FsRedirection(*i r3r3)"
  System::Call 'kernel32::GetSystemDirectoryA(t .r0, *i r1r1) i .r2'
  StrCpy $REALSYSDIR $0

  # remove the driver devnode, files, infs...etc
  ExecWait '"$INSTDIR\removedev.exe" "/d" "XEN\vif"' $0
  DeleteRegKey HKLM SYSTEM\CurrentControlSet\Services\xennet
  DeleteRegKey HKLM SYSTEM\CurrentControlSet\Services\xennet6
  Delete /REBOOTOK $REALSYSDIR\drivers\xennet.sys
  Delete /REBOOTOK $REALSYSDIR\drivers\xennet6.sys
  Push "XEN\vif"
  Call un.DeleteInstalledOemInf
  
  # remove the driver devnode, files, infs...etc
  ExecWait '"$INSTDIR\removedev.exe" "/d" "XEN\vwif"' $0
  DeleteRegKey HKLM SYSTEM\CurrentControlSet\Services\xenwnet
  DeleteRegKey HKLM SYSTEM\CurrentControlSet\Services\xenwnet6
  Delete /REBOOTOK $REALSYSDIR\drivers\xenwnet.sys
  Delete /REBOOTOK $REALSYSDIR\drivers\xenwnet6.sys
  Push "XEN\vwif"
  Call un.DeleteInstalledOemInf

  ${If} "$OsType" == "7" 
  ${OrIf} "$OsType" == "8Plus" 
    ExecWait '"$INSTDIR\removedev.exe" "/d" "XEN\vusb"' $0
    DeleteRegKey HKLM SYSTEM\CurrentControlSet\Services\xenvusb
    Delete /REBOOTOK $REALSYSDIR\drivers\xenvusb.sys
    Push "XEN\vusb"
    Call un.DeleteInstalledOemInf
  ${EndIf}
  
  ${If} "$OsType" != "2000"
    # remove the driver devnode, files, infs...etc
    ExecWait '"$INSTDIR\removedev.exe" "/d" "XEN\v4v"' $0
    DeleteRegKey HKLM SYSTEM\CurrentControlSet\Services\xenv4v
    Delete /REBOOTOK $REALSYSDIR\drivers\xenv4v.sys
    Push "XEN\v4v"
    Call un.DeleteInstalledOemInf
  ${EndIf}
  
!ifdef INSTALL_XENVESA
  ExecWait '"$INSTDIR\removedev.exe" "/d" "PCI\VEN_1234&DEV_1111&SUBSYS_00015853"' $0
  ExecWait '"$INSTDIR\removedev.exe" "/d" "PCI\VEN_1234&DEV_1111"' $0
${If} "$OsType" != "8Plus"
  DeleteRegKey HKLM SYSTEM\CurrentControlSet\Services\xenvesa-miniport
  Delete /REBOOTOK $REALSYSDIR\drivers\xenvesa-miniport.sys
  Delete /REBOOTOK $REALSYSDIR\drivers\xenvesa-display.dll
${EndIf}
  Push "PCI\VEN_1234&DEV_1111&SUBSYS_00015853"
  Call un.DeleteInstalledOemInf
	Push "PCI\VEN_1234&DEV_1111"
	Call un.DeleteInstalledOemInf
!endif

  ExecWait '"$INSTDIR\removedev.exe" "/d" "PCI\VEN_5853&DEV_C110&SUBSYS_C1105853"' $0
  ExecWait '"$INSTDIR\removedev.exe" "/d" "PCI\VEN_5853&DEV_C110"' $0
  DeleteRegKey HKLM SYSTEM\CurrentControlSet\Services\xeninp
  Delete /REBOOTOK $REALSYSDIR\drivers\xeninp.sys
  Push "PCI\VEN_5853&DEV_C110&SUBSYS_C1105853"
  Call un.DeleteInstalledOemInf
    Push "PCI\VEN_5853&DEV_C110"
    Call un.DeleteInstalledOemInf
    

  ExecWait '"$INSTDIR\removedev.exe" "/f" "{4D36E967-E325-11CE-BFC1-08002BE10318}" "LowerFilters" "scsifilt"' $0
  ExecWait '"$INSTDIR\removedev.exe" "/d" "PCI\VEN_5853&DEV_0001&SUBSYS_00015853"' $0
  ExecWait '"$INSTDIR\removedev.exe" "/d" "PCI\VEN_5853&DEV_0001"' $0
  DeleteRegKey HKLM SYSTEM\CurrentControlSet\Services\xenvbd
  DeleteRegKey HKLM SYSTEM\CurrentControlSet\Control\CriticalDeviceDatabase\pci#ven_5853&dev_0001&subsys_00015853
  DeleteRegKey HKLM SYSTEM\CurrentControlSet\Control\CriticalDeviceDatabase\pci#ven_5853&dev_0001
  Delete /REBOOTOK $REALSYSDIR\drivers\xenvbd.sys
  Delete /REBOOTOK $REALSYSDIR\drivers\scsifilt.sys
  Push "PCI\VEN_5853&DEV_0001&SUBSYS_00015853"
  Call un.DeleteInstalledOemInf
	Push "PCI\VEN_5853&DEV_0001"
	Call un.DeleteInstalledOemInf

  ExecWait '"$INSTDIR\removedev.exe" "/d" "root\xenevtchn"' $0
  DeleteRegKey HKLM SYSTEM\CurrentControlSet\Services\xenevtchn
  DeleteRegKey HKLM SYSTEM\CurrentControlSet\Services\EventLog\System\xenevtchn
  Delete /REBOOTOK $REALSYSDIR\drivers\xevtchn.sys
  Push "ROOT\XENEVTCHN"
  Call un.DeleteInstalledOemInf

  # We have a problem if Windows removes xenutil.sys before any of the
  # other services.  Make sure it doesn't.
  ExecWait '"$INSTDIR\sync.exe"'

  Delete /REBOOTOK $REALSYSDIR\drivers\xenutil.sys

  # turn off special wow64 handling
  System::Call "kernel32::Wow64RevertWow64FsRedirection(*i r3)"

  DeleteRegKey HKLM ${REG_XENTOOLS_PATH}
  DeleteRegKey HKLM "${REG_UNINSTALL}"

  # Need to remove our uninstaller from the registry before we remove it
  # from the disk.
  ExecWait '"$INSTDIR\sync.exe"'

  Delete /REBOOTOK $INSTDIR\fixdiskfilters.exe
  Delete /REBOOTOK $INSTDIR\copyvif.exe
  Delete /REBOOTOK $INSTDIR\copyvif.log.txt
  Delete /REBOOTOK $INSTDIR\sync.exe
  Delete /REBOOTOK $INSTDIR\uninstaller.exe
  Delete /REBOOTOK $INSTDIR\removedev.exe
  Delete /REBOOTOK $INSTDIR\xenstore_client.exe
  Delete /REBOOTOK $INSTDIR\enableuninst.exe
  Delete /REBOOTOK $INSTDIR\query_balloon.exe
  Delete /REBOOTOK $INSTDIR\getlogs.exe
  Delete /REBOOTOK $INSTDIR\install.dll
  Delete /REBOOTOK $INSTDIR\install.log
  Delete /REBOOTOK $INSTDIR\scsifilt.sys
  Delete /REBOOTOK $INSTDIR\xennet.inf
  Delete /REBOOTOK $INSTDIR\xennet.sys
  Delete /REBOOTOK $INSTDIR\xennet6.sys
  Delete /REBOOTOK $INSTDIR\xennet.cat
  Delete /REBOOTOK $INSTDIR\xenwnet.inf
  Delete /REBOOTOK $INSTDIR\xenwnet.sys
  Delete /REBOOTOK $INSTDIR\xenwnet6.sys
  Delete /REBOOTOK $INSTDIR\xenwnet.cat
  Delete /REBOOTOK $INSTDIR\xenaud.inf
  Delete /REBOOTOK $INSTDIR\xenaud.cat
  Delete /REBOOTOK $INSTDIR\xenaud.sys
  
!ifdef INSTALL_XENVESA
  ${If} "$OsType" != "8Plus"
	Delete /REBOOTOK $INSTDIR\xenvesa-miniport.sys
	Delete /REBOOTOK $INSTDIR\xenvesa-display.dll  
    ${If} "$OsType" == "XP"
      Delete /REBOOTOK $INSTDIR\xenvesa-xp.cat
      Delete /REBOOTOK $INSTDIR\xenvesa-xp.inf
    ${Else}
      Delete /REBOOTOK $INSTDIR\xenvesa-lh.cat
      Delete /REBOOTOK $INSTDIR\xenvesa-lh.inf
    ${EndIF}
  ${EndIf}
!endif
  
	Delete /REBOOTOK $INSTDIR\xeninp.inf
	Delete /REBOOTOK $INSTDIR\xeninp.sys
    Delete /REBOOTOK $INSTDIR\xeninp.cat

  ${If} "$OsType" != "2000"
    Delete /REBOOTOK $INSTDIR\xenv4v.inf
    Delete /REBOOTOK $INSTDIR\xenv4v.sys
    Delete /REBOOTOK $INSTDIR\xenv4v.cat
  ${EndIf}
!ifndef NO_INSTALL_XENSERVICE
  Delete /REBOOTOK $INSTDIR\xenservice.exe
!endif
  Delete /REBOOTOK $INSTDIR\OxtService.exe
  Delete /REBOOTOK $INSTDIR\OxtUserAgent.exe
  Delete /REBOOTOK $INSTDIR\xenvbd.inf
  Delete /REBOOTOK $INSTDIR\xenvbd.sys
  Delete /REBOOTOK $INSTDIR\xenvbd.cat
  Delete /REBOOTOK $INSTDIR\xevtchn.inf
  Delete /REBOOTOK $INSTDIR\xevtchn.sys
  Delete /REBOOTOK $INSTDIR\xevtchn.cat
  Delete /REBOOTOK $INSTDIR\xenutil.sys
  Delete /REBOOTOK $INSTDIR\xs.dll
  Delete /REBOOTOK $INSTDIR\xsutil.dll
  Delete /REBOOTOK $INSTDIR\xs2.dll
  Delete /REBOOTOK $INSTDIR\xs2_32.dll
  RMDir /REBOOTOK $INSTDIR
  
  ${If} "$IsAmd64" == "no"
    Delete /REBOOTOK $INSTDIR\xenvusb.inf
  ${Else}
    Delete /REBOOTOK $INSTDIR\xenvusb64.inf
  ${EndIf}
  Delete /REBOOTOK $INSTDIR\xenvusb.sys
  Delete /REBOOTOK $INSTDIR\xenvusb.cat
  Delete /REBOOTOK $INSTDIR\WdfCoInstaller01009.dll

  ${UnLogText} "....Done."

  SetRebootFlag true

  # Work around NSIS bug: doesn't reboot if in silent mode.
  ${un.GetOptions} $cmdLineParams '/norestart' $R0
  IfErrors 0 end_uninstall
  IfSilent 0 end_uninstall
  IfRebootFlag 0 end_uninstall
  Reboot

  end_uninstall:

SectionEnd ; end the section



LangString DESC_SecDrvInst ${LANG_ENGLISH} "Driver Installation Section."

  
!insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN
  !insertmacro MUI_DESCRIPTION_TEXT ${secDrvInst} $(DESC_SecDrvInst)
!insertmacro MUI_FUNCTION_DESCRIPTION_END

!insertmacro DualUseFunctions_ ""
!insertmacro DualUseFunctions_ "un."
