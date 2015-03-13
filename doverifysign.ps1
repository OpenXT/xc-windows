param
(
  [string]$signtool="signtool"
)
$ScriptDir = Split-Path -parent $MyInvocation.MyCommand.Path
Import-Module $ScriptDir\..\BuildSupport\invoke.psm1

Write-Host "signtool $signtool"
Push-Location sign32
Invoke-CommandChecked "Check 32 bit CAT files" $signtool verify /pa /v xennet.cat xenwnet.cat xenvbd.cat xenvesa-xp.cat xenvesa-lh.cat xenv4v.cat xevtchn.cat xeninp.cat xenaud.cat
Invoke-CommandChecked "Check 32 bit boot start drivers" $signtool verify /pa /v xevtchn.sys xenv4v.sys xenvbd.sys xenvesa-miniport.sys xenvesa-display.dll scsifilt.sys xennet.sys xennet6.sys xenwnet.sys xenwnet6.sys xenutil.sys xeninp.sys xenaud.sys
Pop-Location

Push-Location sign64
Invoke-CommandChecked "Check 64 bit CAT files" $signtool verify /pa /v xennet.cat xenwnet.cat xenvbd.cat  xenvesa-xp.cat xenvesa-lh.cat xenv4v.cat xevtchn.cat xeninp.cat xenaud.cat
Invoke-CommandChecked "Checked 64 bit boot start drivers" $signtool verify /pa /v xevtchn.sys xenv4v.sys xenvbd.sys xenvesa-miniport.sys xenvesa-display.dll scsifilt.sys xennet.sys xennet6.sys xenwnet.sys xenwnet6.sys xenutil.sys xeninp.sys xenaud.sys
Pop-Location
