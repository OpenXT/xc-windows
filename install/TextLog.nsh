# TextLog.nsh v1.1 - 2005-12-26
# Written by Mike Schinkel [http://www.mikeschinkel.com/blog/]
# Modified by Adam Lewis

#######################
## Install Section ##
####################### 
Var /GLOBAL __TextLog_FileHandle
Var /GLOBAL __TextLog_FileName
Var /GLOBAL __TextLog_State
 
!define LogMsg '!insertmacro LogMsgCall'
!macro LogMsgCall _text
    Call LogSetOn
    Push "${_text}"
    Call LogText
    Call LogSetOff
!macroend

!define LogText '!insertmacro LogTextCall'
!macro LogTextCall _text
    Push "${_text}"
    Call LogText
!macroend

Function LogText
    Exch $0       ; pABC -> 0ABC
    FileWrite $__TextLog_FileHandle "$0$\r$\n"
    Pop $0        ; 0ABC -> ABC
FunctionEnd
 
!define LogSetFileName '!insertmacro LogSetFileNameCall'
!macro LogSetFileNameCall _filename
    Push "${_filename}"
    Call LogSetFileName
!macroend
 
Function LogSetFileName
    Exch $0       ; pABC -> 0ABC
    StrCpy $__TextLog_FileName "$0"
    StrCmp $__TextLog_State "open" +1 +3
    Call LogSetOff
    Call LogSetOn
    Pop $0        ; 0ABC -> ABC
FunctionEnd
 
Function LogSetOn
    StrCmp $__TextLog_FileName "" +1 AlreadySet
    StrCpy $__TextLog_FileName "$INSTDIR\install.log"
AlreadySet:
    StrCmp $__TextLog_State "open" +2
    FileOpen $__TextLog_FileHandle  "$__TextLog_FileName"  a
        FileSeek $__TextLog_FileHandle 0 END
    StrCpy $__TextLog_State "open"
FunctionEnd
 
!define LogSetOff '!insertmacro LogSetOffCall'
!macro LogSetOffCall
     Call LogSetOff
!macroend
 
Function LogSetOff
    StrCmp $__TextLog_State "open" +1 +2
    FileClose $__TextLog_FileHandle
    StrCpy $__TextLog_State ""
FunctionEnd


!define LogSetOn '!insertmacro LogSetOnCall'
!macro LogSetOnCall
    Call LogSetOn
!macroend

#######################
## Uninstall Section ##
#######################
!define UnLogMsg '!insertmacro un.LogMsgCall'
!macro un.LogMsgCall _text
    Call un.LogSetOn
    Push "${_text}"
    Call un.LogText
    Call un.LogSetOff
!macroend

!define UnLogText '!insertmacro un.LogTextCall'
 !macro un.LogTextCall _text
    Push "${_text}"
    Call un.LogText
!macroend

Function un.LogText
    Exch $0       ; pABC -> 0ABC
    FileWrite $__TextLog_FileHandle "$0$\r$\n"
    Pop $0        ; 0ABC -> ABC
FunctionEnd
 
!define UnLogSetFileName '!insertmacro un.LogSetFileNameCall'
!macro un.LogSetFileNameCall _filename
    Push "${_filename}"
    Call un.LogSetFileName
!macroend
 
Function un.LogSetFileName
    Exch $0       ; pABC -> 0ABC
    StrCpy $__TextLog_FileName "$0"
    StrCmp $__TextLog_State "open" +1 +3
    Call un.LogSetOff
    Call un.LogSetOn
    Pop $0        ; 0ABC -> ABC
FunctionEnd
 
Function un.LogSetOn
    StrCmp $__TextLog_FileName "" +1 AlreadySet
    StrCpy $__TextLog_FileName "$INSTDIR\install.log"
AlreadySet:
    StrCmp $__TextLog_State "open" +2
    FileOpen $__TextLog_FileHandle  "$__TextLog_FileName"  a
    FileSeek $__TextLog_FileHandle 0 END
    StrCpy $__TextLog_State "open"
FunctionEnd
 
!define UnLogSetOff '!insertmacro un.LogSetOffCall'
!macro un.LogSetOffCall
     Call un.LogSetOff
!macroend
 
Function un.LogSetOff
    StrCmp $__TextLog_State "open" +1 +2
    FileClose $__TextLog_FileHandle
    StrCpy $__TextLog_State ""
FunctionEnd


!define UnLogSetOn '!insertmacro un.LogSetOnCall'
!macro un.LogSetOnCall
    Call un.LogSetOn
!macroend