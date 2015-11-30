$ErrorActionPreference = 'stop'
$ScriptDir = Split-Path -parent $MyInvocation.MyCommand.Path
Import-Module $ScriptDir\..\BuildSupport\invoke.psm1
Import-Module $ScriptDir\..\BuildSupport\checked-copy.psm1
#Helper Functions
function enable-read-execute([string]$file)
{
    $acl = Get-Acl $file
    $ar = New-Object System.Security.Accesscontrol.FileSystemAccessRule("Everyone", "ReadAndExecute", "Allow")
    $acl.SetAccessRule($ar)
    Set-Acl $file $acl
}



#Get parameters
$args | Foreach-Object {$argtable = @{}} {if ($_ -Match "(.*)=(.*)") {$argtable[$matches[1]] = $matches[2];}}
$ddkdir = $argtable["DdkDir"]
$licfile = $argtable["License"]
$type = $argtable["BuildType"]
$developer = $argtable["Developer"]
$signtool = $argtable["SignTool"]
$certname = $argtable["CertName"]
$VSDir = $argtable["VSDir"]
$verstr = $argtable["VerString"]
$ver0 = $argtable["VerMajor"]
$ver1 = $argtable["VerMinor"]
$ver2 = $argtable["VerMicro"]
$ver3 = $argtable["BuildNumber"]
$tag = $argtable["BuildTag"]
$branch = $argtable["BuildBranch"]
$MSBuild = $argtable["MSBuild"]
$giturl = $argtable["GitUrl"]
$gitbin = $argtable["GitBin"]
$crosssign = $argtable["CrossSign"]
$compile = $true # can be set to false if you just want to get to signing quickly

#Set some important variables
$mywd = Split-Path -Parent $MyInvocation.MyCommand.Path

if ($signtool.Length -lt 1) {
    throw "Please specify the location of a directory containing signtool using the /signtool argument"
}

Push-Location -Path $mywd

#Set build type
$cfg = "fre"
if ($type.ToLower().CompareTo("debug") -eq 0)
{
	$cfg = "chk"
}



Write-Host ("Building Xen Tools version: " + $verstr + " in: " + $mywd)

# Before running any of the batch files, make sure they have an access rule to allow execute
enable-read-execute -file ".\dostampinf.bat"
enable-read-execute -file ".\dobuild.bat"
enable-read-execute -file ".\dowin8build.bat"
enable-read-execute -file ".\doverifysign.ps1"
enable-read-execute -file ".\dotestsign.bat"

# If no specific license is specified, grab the default EULA
if ($licfile.Length -lt 1)
{
    $licfile = $mywd + "\xenclient-eula\EULA-en-us"
}

# Modify the findddk.bat to use the DDK specified for the build. If you suspect this is a hack
# you would be correct my friend...
Set-Content -Path ".\findddk.bat" -Value ("set ddk_path=" + $ddkdir)
if ($compile) {
    Invoke-CommandChecked "Timestamping INF files"  ".\dostampinf.bat" $ddkdir $mywd $verstr
    Invoke-CommandChecked "Building 32 bit bits" ".\dobuild.bat" $ddkdir $mywd $cfg "x86"
    Invoke-CommandChecked "Building 64 bit bits" ".\dobuild.bat" $ddkdir $mywd $cfg "x64"
    Invoke-CommandChecked "Building Win8 32 bit bits" ".\dowin8build.bat" $VSDir $mywd $cfg "x86"
    Invoke-CommandChecked "Building Win8 64 bit bits" ".\dowin8build.bat" $VSDir $mywd $cfg "x64"
}

Push-Location

# TODO: use the logic in openxt.git/windows/winbuild-all.ps1 to do git clones rather than 
# have this logic that duplicates it. Cope with the way that will checkout xc-vusb one
# level higher, i.e. as a peer of xc-windows not a subdirecory of xc-windows.
$gitsrc = $giturl + "/" + "xc-vusb.git"
$doclone = $true
# skip the clone if it has already been done
if (Test-Path ("xc-vusb\.git")) {
    $nfiles = (Get-ChildItem "xc-vusb").Count
    # it is possible a failure during an earlier clone resulted in a directory,
    # possibly with a .git subdirectory, so if we see that we still need to clone
    if ([int]$nfiles -gt 1) {
        $doclone = $false
    }
}

if ($doclone) {
    Invoke-CommandChecked "git clone xc-vusb" $gitbin clone "-n" $gitsrc
    Invoke-CommandChecked "git fetch origin" $gitbin fetch origin
    if ($branch.Length -gt 0) {
        Push-Location -Path "xc-vusb"
        Write-Host ("Checking out: " + $branch + " For: xc-vusb")
        if ($branch.CompareTo("master") -eq 0) {
            Invoke-CommandChecked "git checkout" $gitbin checkout -q $branch
        } else {
            & $gitbin checkout -q origin/$branch
	    # standard practice on XT is to fall back to master for
	    # branches that do not exist.
            if (-Not ($LastExitCode -eq 0)) {
                 Invoke-CommandChecked "git checkout" $gitbin checkout -q -b $branch
            }
        } 
        Pop-Location 
    } elseif ($tag.Length -gt 0) {
       Push-Location -Path "xc-vusb"
       Write-Host ("Checking out: " + $tag + " For: xc-vusb")
       Invoke-CommandChecked "git checkout tag for xc-vusb" $gitbin checkout -q -b $tag $tag 
       Pop-Location
    } else {
       throw "No branch or tag for xc-vusb checkout"
    }
}

#Build xc-vusb
$usbBuild = "Win7 $type"
if ($compile) {
    Invoke-CommandChecked "xc-vusb msbuild 32 bit" $MSBuild xc-vusb\Drivers\xenvusb\xenvusb.sln /p:Configuration=$usbBuild
    Invoke-CommandChecked "xc-vusb msbuild 64 bit" $MSBuild xc-vusb\Drivers\xenvusb\xenvusb.sln /p:Configuration=$usbBuild /p:Platform="x64"
}

New-Item -Path ".\xc-vusb\build\x86" -Type Directory -Force
New-Item -Path ".\xc-vusb\build\x64" -Type Directory -Force
 
if ($type.ToLower().CompareTo("debug") -eq 0) {
    Checked-Copy ".\xc-vusb\Drivers\xenvusb\xenvusb.inf" ".\xc-vusb\build\x86\"
    Checked-Copy ".\xc-vusb\Drivers\xenvusb\Win7Debug\xenvusb.sys" ".\xc-vusb\build\x86\"    
    Checked-Copy ".\xc-vusb\Drivers\xenvusb\xenvusb64.inf" ".\xc-vusb\build\x64\xenvusb.inf"
    Checked-Copy ".\xc-vusb\Drivers\xenvusb\x64\Win7Debug\xenvusb.sys" ".\xc-vusb\build\x64\"
} else {
    Checked-Copy ".\xc-vusb\Drivers\xenvusb\xenvusb.inf" ".\xc-vusb\build\x86\"
    Checked-Copy ".\xc-vusb\Drivers\xenvusb\Win7Release\xenvusb.sys" ".\xc-vusb\build\x86\"    
    Checked-Copy ".\xc-vusb\Drivers\xenvusb\xenvusb64.inf" ".\xc-vusb\build\x64\xenvusb.inf"
    Checked-Copy ".\xc-vusb\Drivers\xenvusb\x64\Win7Release\xenvusb.sys" ".\xc-vusb\build\x64\"
}

if ($crosssign) {
    Invoke-CommandChecked "do_sign" powershell ./do_sign.ps1 -certname ("'"+$certname+"'") -signtool ("'"+$signtool+"'") -crosssign ("'"+$crosssign+"'")
} else {
    Invoke-CommandChecked "do_sign" powershell ./do_sign.ps1 -certname ("'"+$certname+"'") -signtool ("'"+$signtool+"'")
}
 
#Only do verification if not doing a developer build
if($developer -ne $true){
    #Verify the drivers are signed using default signtool through %PATH% or use a specific one
    Invoke-CommandChecked "doverifysign" .\doverifysign.ps1 $signtool\signtool.exe
}

Pop-Location

# Change dir and copy the default EULA or specified license to install folder
Push-Location -Path "install"
Checked-Copy $licfile ".\license.txt" 

# Package the NSIS installer - need the individual version numbers here
Write-Host "Building driver installer"

Invoke-CommandChecked "makensis" makensis "/DINSTALL_XENVESA" "/DINSTALL_XENVESA8" ("/DVERMAJOR=" + $ver0) ("/DVERMINOR=" + $ver1) ("/DVERMICRO=" + $ver2) ("/DVERBUILD=" + $ver3) "xensetup.nsi"

if (!(Test-Path -Path ".\xensetup.exe" -PathType Leaf))
{
	log-error -err "Failed to make xensetup.exe installer package"
	return $false
}

Pop-Location
Pop-Location
return $true
