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

#Set some important variables
$mywd = Split-Path -Parent $MyInvocation.MyCommand.Path

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
enable-read-execute -file ".\docrosssign.bat"
enable-read-execute -file ".\doverifysign.bat"
enable-read-execute -file ".\dotestsign.bat"
enable-read-execute -file ".\findddk.bat"

# If no specific license is specified, grab the default EULA
if ($licfile.Length -lt 1)
{
    $licfile = $mywd + "\xenclient-eula\EULA-en-us"
}

# Modify the findddk.bat to use the DDK specified for the build. If you suspect this is a hack
# you would be correct my friend...
Set-Content -Path ".\findddk.bat" -Value ("set ddk_path=" + $ddkdir)

# Timestamp the INF files
Write-Host "Timestamping INF files"
& ".\dostampinf.bat" $ddkdir $mywd $verstr

# Build both 32b and 64b targets, Win7 and Win8
Write-Host "Building 32 bit bits"
& ".\dobuild.bat" $ddkdir $mywd $cfg "x86"
Write-Host "Building 64 bit bits"
& ".\dobuild.bat" $ddkdir $mywd $cfg "x64"

# Build Win8 stuff
Write-Host "Building Win8 32 bit bits"
& ".\dowin8build.bat" $VSDir $mywd $cfg "x86"
Write-Host "Building Win8 64 bit bits"
& ".\dowin8build.bat" $VSDir $mywd $cfg "x64"
Push-Location

Invoke-Expression ("git clone -n git://git.xci-test.com/xenclient/xc-vusb.git 2>&1") #Do checkout

if ($LastExitCode -eq 0){
# If a branch has been specified in the config, checkout HEAD of that branch over tag info
	if ($branch.Length -gt 0)
	{
		Push-Location -Path "xc-vusb"
		Write-Host ("Checking out: " + $branch + " For: xc-vusb")
		Invoke-Expression ("git fetch origin 2>&1") #Do checkout
		Invoke-Expression ("git checkout -q origin/$branch -b $branch 2>&1") #Do checkout
		
		#If error, just do a checkout defaulted to master
		if($?){
			Invoke-Expression ("git checkout -q -b $branch 2>&1") #Do checkout
		}
		
		Pop-Location
	}elseif ($tag.Length -gt 0)
	{
		Push-Location -Path "xc-vusb"
		Write-Host ("Checking out: " + $tag + " For: xc-vusb")
		Invoke-Expression ("git checkout -q -b " + $tag + " " + $tag + " 2>&1") #Do checkout
		Pop-Location
	}
} else {
	return 2
}

#Build xc-vusb
$usbBuild = "Win7 $type"
& $MSBuild xc-vusb\Drivers\xenvusb\xenvusb.sln /p:Configuration=$usbBuild
& $MSBuild xc-vusb\Drivers\xenvusb\xenvusb.sln /p:Configuration=$usbBuild /p:Platform="x64"

New-Item -Path ".\xc-vusb\build\x86" -Type Directory -Force
New-Item -Path ".\xc-vusb\build\x64" -Type Directory -Force
 
if ($type.ToLower().CompareTo("debug") -eq 0) {
    Copy-Item ".\xc-vusb\Drivers\xenvusb\xenvusb.inf" ".\xc-vusb\build\x86\"
    Copy-Item ".\xc-vusb\Drivers\xenvusb\Win7Debug\xenvusb.sys" ".\xc-vusb\build\x86\"    
    Copy-Item ".\xc-vusb\Drivers\xenvusb\xenvusb64.inf" ".\xc-vusb\build\x64\"
    Copy-Item ".\xc-vusb\Drivers\xenvusb\x64\Win7Debug\xenvusb.sys" ".\xc-vusb\build\x64\"
} else {
    Copy-Item ".\xc-vusb\Drivers\xenvusb\xenvusb.inf" ".\xc-vusb\build\x86\"
    Copy-Item ".\xc-vusb\Drivers\xenvusb\Win7Release\xenvusb.sys" ".\xc-vusb\build\x86\"    
    Copy-Item ".\xc-vusb\Drivers\xenvusb\xenvusb64.inf" ".\xc-vusb\build\x64\"
    Copy-Item ".\xc-vusb\Drivers\xenvusb\x64\Win7Release\xenvusb.sys" ".\xc-vusb\build\x64\"
}

Push-Location
& ".\docrosssign.bat" $mywd $certname
Pop-Location

#Only do verification if not doing a developer build
if($developer -ne $true){
    #Verify the drivers are signed using default signtool through %PATH% or use a specific one
    if ($signtool.Length -lt 1)
    {
        & ".\doverifysign.bat"
    }
    else
    {
        & ".\doverifysign.bat" $signtool
    }
    if (!($?))
    {
        Write-Host "Signature verification failed"
        return $false
    }
}

Pop-Location

# Change dir and copy the default EULA or specified license to install folder
Push-Location -Path "install"
Copy-Item -Path $licfile -Destination ".\license.txt" -Force -Verbose

# Package the NSIS installer - need the individual version numbers here
Write-Host "Building driver installer"

& makensis "/DINSTALL_XENVESA" "/DINSTALL_XENVESA8" ("/DVERMAJOR=" + $ver0) ("/DVERMINOR=" + $ver1) ("/DVERMICRO=" + $ver2) ("/DVERBUILD=" + $ver3) "xensetup.nsi"

if (!(Test-Path -Path ".\xensetup.exe" -PathType Leaf))
{
	log-error -err "Failed to make xensetup.exe installer package"
	return $false
}

Pop-Location
Pop-Location
return $true
