##################################
# GetWindowsVersion() function
# cut & paste and modified from nsis website
##################################
Function GetWindowsVersion

  Push $R0
  Push $R1

  ClearErrors

  ReadRegStr $R1 HKLM \
  "SOFTWARE\Microsoft\Windows NT\CurrentVersion" CurrentVersion
 
  IfErrors 0 lbl_winnt
  
  ; we are not NT
  ReadRegStr $R1 HKLM \
  "SOFTWARE\Microsoft\Windows\CurrentVersion" VersionNumber

  StrCpy $R2 $R1 1
  StrCmp $R2 '4' 0 lbl_error
 
  StrCpy $R2 $R1 3
 
  StrCmp $R2 '4.0' lbl_win32_95
  StrCmp $R2 '4.9' lbl_win32_ME lbl_win32_98
 
lbl_win32_95:
    StrCpy $R1 '95'
  Goto lbl_done
 
lbl_win32_98:
    StrCpy $R1 '98'
  Goto lbl_done
 
lbl_win32_ME:
    StrCpy $R1 'ME'
  Goto lbl_done
 
lbl_winnt:

  System::Call 'install::GetServicePack() i.R0'

  StrCpy $R2 $R1 1
 
  StrCmp $R2 '3' lbl_winnt_x
  StrCmp $R2 '4' lbl_winnt_x
 
  StrCpy $R2 $R1 3
 
  StrCmp $R2 '5.0' lbl_winnt_2000
  StrCmp $R2 '5.1' lbl_winnt_XP
  StrCmp $R2 '5.2' lbl_winnt_2003
  StrCmp $R2 '6.0' lbl_winnt_vista
  StrCmp $R2 '6.1' lbl_winnt_7 
  StrCmp $R2 '6.2' lbl_winnt_8 lbl_error
 
lbl_winnt_x:
    StrCpy $R1 "NT $R1" 6
  Goto lbl_done
 
lbl_winnt_2000:
    Strcpy $R1 '2000'
  Goto lbl_done
 
lbl_winnt_XP:
    Strcpy $R1 'XP'
  Goto lbl_done
 
lbl_winnt_2003:
    Strcpy $R1 '2003'
  Goto lbl_done

lbl_winnt_vista:
    System::Call 'install::GetProductType() i.R1'
    Strcpy $R2 $R1 1
    StrCmp $R2 '1' 0 lbl_winnt_2008
    Strcpy $R1 'Vista'
  Goto lbl_done

lbl_winnt_2008:
    Strcpy $R1 '2008'
  Goto lbl_done
 
lbl_winnt_7:
    System::Call 'install::GetProductType() i.R1'
    Strcpy $R2 $R1 1
    StrCmp $R2 '1' 0 lbl_winnt_2008r2
    Strcpy $R1 '7'
  Goto lbl_done

lbl_winnt_8:
	Strcpy $R1 '8'
  Goto lbl_done

lbl_winnt_2008r2:
    Strcpy $R1 '2008r2'
  Goto lbl_done

lbl_error:
    Strcpy $R1 'Error'

lbl_done:
  Exch $R1
  Exch 
  Exch $R0
   
FunctionEnd