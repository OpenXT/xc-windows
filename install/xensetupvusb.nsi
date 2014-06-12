;
; xensetup.nsi
;


;--------------------------------
!include "MUI.nsh"
!include "LogicLib.nsh"
!include "StrFunc.nsh"
!include "FileFunc.nsh"
!include "winver.nsh"
!include "library.nsh"

# Declare used functions
${StrTok}
${UnStrTok}

!define myFindExistingDevice "install::FindExistingDevice(t,) i"

!define REG_UNINSTALL "Software\Microsoft\Windows\CurrentVersion\Uninstall\OpenXT Xen VUSB"
!define REG_XENTOOLS_PATH "SOFTWARE\OpenXT\XenVUSB"

!define BUILD_PREFIX "..\build\i386"
!define BUILD_PREFIX64 "..\build\amd64"

# OsType is one of 2008r2, 7, 2008, Vista, 2003, XP, and 2000.
Var /GLOBAL OsType
Var /GLOBAL ServicePack

# yes if the host is amd64, no if it's x86.  Note that
# %PROCESSOR_ARCHITECTURE% won't give the right value, since the
# installer is 32 bit anyway.
Var /GLOBAL IsAmd64

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

!define ProductName "Xen VUSB"
!define CompanyName "OpenXT"
!define LegalCopyright " "

!define FileDescription "Installer"

Var /GLOBAL REALSYSDIR

; Execution level
RequestExecutionLevel admin

; Branding text on the installer
BrandingText "${ProductName} ${CurrentMajorVersion}.${CurrentMinorVersion}.${CurrentMicroVersion}"

!define MUI_ICON "..\media\xen.ico"
!define MUI_UNICON "..\media\xen.ico"
!define MUI_WELCOMEFINISHPAGE_BITMAP "DialogInstall.bmp"
!define MUI_UNWELCOMEFINISHPAGE_BITMAP "DialogInstall.bmp"

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
OutFile "xensetupvusb.exe"

; The default installation directory
InstallDir $PROGRAMFILES\OpenXT\XenTools

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
LogText "No pnputil"
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
LogText "No pnputil"
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
LogText "Windows version detected - $OsType, Service Pack - $ServicePack"

${If} "$OsType" == "XP"
   Goto version_mismatch
${ElseIf} "$OsType" == "2000"
   Goto version_mismatch
${EndIf}

Goto next_check

version_mismatch:
StrCmp $ServicePack "" no_servicepack
StrCpy $R3 "$OsType (SP$ServicePack)"
Goto printMessage
no_servicepack:
StrCpy $R3 $OsType

printMessage:
MessageBox MB_YESNO|MB_ICONQUESTION "You are running Windows $R3.  Only Windows Server 2008 and Vista onward are supported. Do you want to continue?" /SD IDYES IDNO stop
Goto next_check

next_check:

# What kind of processor do we have?
System::Call 'install::IsAmd64() i.r0'
${If} $0 = 1
   StrCpy $IsAmd64 "yes"
${Else}
   StrCpy $IsAmd64 "no"
${EndIf}

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
IntCmp $0 1 done

StrCpy $PciDeviceName "PCI\VEN_5853&DEV_0001"
System::Call '${myFindExistingDevice}?e ("$PciDeviceName") .r0'
Pop $1 ; last error
DetailPrint "pci device detected - $0 $1"
IntCmp $0 1 done dev_notfound

    MessageBox MB_OK 'Unable to find/load FindExistingDevice() in install.dll'
    Strcpy $R0 'fail'
    Goto done

dev_notfound:
    MessageBox MB_OK "Unable to detect a valid platform."
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

####################
# Install section
####################
Section "Install Section" SecDrvInst ;No components page, name is not important
  
  LogSet on

  # Always use 32 bit install.dll, since the installer is a 32 bit
  # application.
  SetOutPath $TEMP
  File "${BUILD_PREFIX}\install.dll"

  LogText "Preinstall checks..."
  DetailPrint "Preinstall checks..."

  Call PreInstallCheck
  Pop $R2
  Delete $TEMP\install.dll
  StrCmp $R2 "fail" done
  
  ${GetParameters} $cmdLineParams

  WriteRegDWORD HKLM ${REG_XENTOOLS_PATH} "MajorVersion" ${CurrentMajorVersion}
  WriteRegDWORD HKLM ${REG_XENTOOLS_PATH} "MinorVersion" ${CurrentMinorVersion}
  WriteRegDWORD HKLM ${REG_XENTOOLS_PATH} "MicroVersion" ${CurrentMicroVersion}
  WriteRegDWORD HKLM ${REG_XENTOOLS_PATH} "BuildVersion" ${CurrentBuildVersion}
  WriteRegStr   HKLM ${REG_XENTOOLS_PATH} "Install_Dir" "$INSTDIR" 

  LogText "Copying files to $INSTDIR..."
  
  SetOutPath $INSTDIR

  ${If} "$IsAmd64" == "no"

!ifdef INSTALL_DEBUG
    File ..\xc-vusb\Drivers\xenvusb\Win7Debug\xenvusb.sys
!else
	File ..\xc-vusb\Drivers\xenvusb\Win7Release\xenvusb.sys
!endif
    File /nonfatal ..\xc-vusb\Drivers\xenvusb\xenvusb.cat
    File ..\xc-vusb\Drivers\xenvusb\xenvusb.inf
	File .\WdfCoInstaller01009.dll

    File ${BUILD_PREFIX}\removedev.exe
  
  ${Else}

!ifdef INSTALL_DEBUG
    File ..\xc-vusb\Drivers\xenvusb\x64\Win7Debug\xenvusb.sys
!else
    File ..\xc-vusb\Drivers\xenvusb\x64\Win7Release\xenvusb.sys
!endif
	File /nonfatal /oname=xenvusb.cat ..\xc-vusb\Drivers\xenvusb\xenvusb64.cat
	File /oname=xenvusb.inf ..\xc-vusb\Drivers\xenvusb\xenvusb64.inf
	File .\WdfCoInstaller01009.dll

    File ${BUILD_PREFIX64}\removedev.exe

  ${EndIf}

  LogText "File copy done."

  # Remove old drivers
  Push "XEN\VUSB"
  Call DeleteInstalledOemInf

  # Install drivers
  SetOutPath $TEMP
  ${if} "$IsAmd64" == "yes"
    File ${BUILD_PREFIX64}\installdriver.exe
  ${else}
    File ${BUILD_PREFIX}\installdriver.exe
  ${endif}
  ClearErrors
  
InstallINFs:
  
  ExecWait '"$TEMP\installdriver.exe" "/i" "$HWNDPARENT" "$INSTDIR\xenvusb.inf"' $0

  IfErrors error
  IntCmp "$0" 0 0 error
  
  LogText "Installing xenv4v driver..."
  DetailPrint "Installing xenv4v driver..."
  ${If} $R0 == "New"
    ExecWait '"$TEMP\installdriver.exe" "/p" "$HWNDPARENT" "XEN\vusb" "$INSTDIR\xenvusb.inf" "0"' $0
  ${else}
    ExecWait '"$TEMP\installdriver.exe" "/p" "$HWNDPARENT" "XEN\vusb" "$INSTDIR\xenvusb.inf" "1"' $0
  ${endif}
  IfErrors error
  IntCmp "$0" 0 0 error
  IntCmp "$0" 0 0 error

  LogText "Drivers/service installation done."
  DetailPrint "Drivers/service installation done."
  
  LogText "Generating uninstaller.exe..."
  DetailPrint "Generating uninstaller.exe..."

  writeUninstaller $INSTDIR\uninstaller.exe

  WriteRegStr HKLM "${REG_UNINSTALL}" "DisplayVersion" ${CurrentMajorVersion}.${CurrentMinorVersion}.${CurrentBuildVersion}
  WriteRegStr HKLM "${REG_UNINSTALL}" "DisplayName" "${ProductName}"
  WriteRegStr HKLM "${REG_UNINSTALL}" "Publisher" "${CompanyName}"
  WriteRegStr HKLM "${REG_UNINSTALL}" "DisplayIcon" "$INSTDIR\uninstaller.exe,0"
  WriteRegStr HKLM "${REG_UNINSTALL}" "UninstallString" "$INSTDIR\uninstaller.exe /cxmi"
  WriteRegDWord HKLM "${REG_UNINSTALL}" "NoModify" 1
  WriteRegDWord HKLM "${REG_UNINSTALL}" "NoRepair" 1

  SetRebootFlag true
  Goto done

error:
  MessageBox MB_OK "An error has been encountered during installation! Please check the install log for details."
  DeleteRegKey HKLM ${REG_XENTOOLS_PATH}

done:
  Delete "$TEMP\installdriver.exe"

  ${GetOptions} $cmdLineParams '/norestart' $R0
  IfErrors 0 end
  IfSilent 0 end
  IfRebootFlag 0 end
  LogText "Rebooting."
  Reboot

end:
SectionEnd ; end the section


####################
# Uninstall section
####################
Section "Uninstall"

  System::Call "kernel32::GetModuleHandle(t 'shell32.dll') i .s"
  System::Call "kernel32::GetProcAddress(i s, i 680) i .r0"
  System::Call "::$0() i .r0"
  ${If} "$0" <> 1
    MessageBox MB_OK "You must be an administrator to uninstall ${ProductName}."
    goto end_uninstall
  ${EndIf}
  
  SetOutPath $INSTDIR

  LogText "Uninstalling..."
  
  # Get the real system directory.  This is needed to delete files on x64
  System::Call "kernel32::Wow64DisableWow64FsRedirection(*i r3r3)"
  System::Call 'kernel32::GetSystemDirectoryA(t .r0, *i r1r1) i .r2'
  StrCpy $REALSYSDIR $0

  # remove the driver devnode, files, infs...etc
  ExecWait '"$INSTDIR\removedev.exe" "/d" "XEN\vusb"' $0
  DeleteRegKey HKLM SYSTEM\CurrentControlSet\Services\xenvusb
  Delete /REBOOTOK $REALSYSDIR\drivers\xenvusb.sys
  Push "XEN\vusb"
  Call un.DeleteInstalledOemInf

  # turn off special wow64 handling
  System::Call "kernel32::Wow64RevertWow64FsRedirection(*i r3)"

  DeleteRegKey HKLM ${REG_XENTOOLS_PATH}
  DeleteRegKey HKLM "${REG_UNINSTALL}"

  Delete /REBOOTOK $INSTDIR\uninstaller.exe
  Delete /REBOOTOK $INSTDIR\removedev.exe
  Delete /REBOOTOK $INSTDIR\install.dll
  Delete /REBOOTOK $INSTDIR\install.log

  Delete /REBOOTOK $INSTDIR\xenvusb.inf
  Delete /REBOOTOK $INSTDIR\xenvusb.sys
  Delete /REBOOTOK $INSTDIR\xenvusb.cat

  LogText "....Done."

  SetRebootFlag true

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
