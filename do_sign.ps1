param
(
    [string]$certname,
    [string]$signtool,
    [string]$crosssign = ""
)

$badsys = @("xenm2b.sys", "xengfxmp.sys", "xengfxwd.sys")
$badinfs = @("xenm2b.inf")
$extrainfs = @("xenvesa-lh.inf", "xenvesa-xp.inf", "xeninp.inf", "xenVesaDO.inf")

$ScriptDir = Split-Path -parent $MyInvocation.MyCommand.Path
Import-Module $ScriptDir\..\BuildSupport\invoke.psm1
Import-Module $ScriptDir\..\BuildSupport\checked-copy.psm1

function sign ($arch, $name) { 
    Write-Host "signing with [$certname] crosssign [$crosssign]"
    if ($crosssign) {
        Invoke-CommandChecked "$arch signtool " ($signtool+"\signtool.exe") sign /v /a /s my /n ('"'+$certname+'"') /t http://timestamp.verisign.com/scripts/timestamp.dll /ac $crosssign $name 
    } else {
        Invoke-CommandChecked "$arch signtool " ($signtool+"\signtool.exe") sign /v /a /s my /n ('"'+$certname+'"') /t http://timestamp.verisign.com/scripts/timestamp.dll  $name 
    }
}

foreach ($arch in @("amd64", "i386")) {
    if ($arch -eq "i386") {
        $workd = "sign32"
	$oslist = "/os:2000,XP_X86,Server2003_X86,Vista_X86,Server2008_X86"
	$vusb_arch = "x86" # TODO: use the same build directory name on xc-vusb to avoid needing to handle it separately heere
    } else {
        $workd = "sign64"
	$oslist = "/os:XP_X64,Server2003_X64,Vista_X64,Server2008_X64"
	$vusb_arch = "x64"
    }
    # TODO: make this work incrementally. For now we just delete the siging directory tree
    # difficulties: signtool signs file in place
    if (Test-Path $workd) {
        Remove-Item -Recurse -Force $workd # delete $workd directory tree
    }
    mkdir $workd
    Push-Location $workd
    Write-Host "Copying sys files to $workd"
    # TODO: consider combining the build and xc-vusb/build directories
    # to simplify this code
    # TODO: run signtool once with all the sys files as arguments
    $failed = $false
    foreach ($buildd in @("..\build\$arch", "..\xc-vusb\build\$vusb_arch")) {
        Get-ChildItem $buildd -Filter *.sys | Foreach-Object {
	    try {
      	        if (! ($badsys -contains ([string]$_))) {
                    Checked-Copy ($_.FullName) $_
                    sign $arch $_ $certname
                    Checked-Copy $_ ($_.FullName)
                }
            } catch {
                Write-Host "Failed to copy and sign sys file $_ with $_Exception.Message"
                $failed = $true
            }
        }
    }
    if ($failed) {
        throw "copying and signing sys files failed"
    }
    Write-Host "Copying inf files to $workd"
    $failed = $false
    Get-ChildItem ..\ -Filter *.inf -Recurse | Where {! ($_.FullName -like ('*\sign*'))} | Foreach-Object {
        try {
            # we need to leave out certain inf files on specific architectures
            # TODO: get rid of the bad inf files from the build so that we
    	    # don't need this code
	    $handle = $true
	    if ($badinfs -contains ([string]$_)) {
	        $handle = $false
            }
            # we want inf files that correspond to the sys files we have
	    $base = ($_.BaseName)
	    # TODO: rename the inf files to just have the architecture
	    # as a postfix to simplify this code
            if ($arch -eq "amd64") {
  	        if ($base.EndsWith("64")) {
                    $base = $base.Substring(0, $base.Length-2)
                } else {
   	            $handle = $false
                }
            }
            if ($handle -and (Test-Path ($base+'.sys'))) {
				Checked-Copy $_.FullName ($_.Name).Replace("64","")
            }
            # and there are some extra inf files which don't have names
            # matching sys files
            if ($extrainfs -contains ([string]$_)) {
	        Checked-Copy $_.FullName ($_.Name).Replace("64","")
            }
	    # TODO: make the extra inf files match the pattern above to simplify this code
        } catch {
            $failed = $true
            Write-Host "Failed to process inf file $_ with $_Exception.Message"
        }
    }
    if ($failed) {
        throw "inf file handling failed"
    }
    Checked-Copy ..\install\WdfCoInstaller01009.dll .
    Checked-Copy ..\build\$arch\xenvesa-display.dll .
    sign $arch xenvesa-display.dll
    Invoke-CommandChecked "inf2cat $arch" ($signtool+"/inf2cat") /driver:. $oslist
    $failed = $false
    Get-ChildItem . -Filter *.cat | Foreach-Object {
        try {
            sign $arch $_
        } catch {
            $failed = $true
            Write-Host "sign $_ failed with $_Exception.Message"
        }
    }
    #Write-Host "Copying cat files matching inf files back $(get-location)"
    # copy back the new cat files alongside their inf files
    #$failed = $false
    # TODO: is this needed?
    #Get-ChildItem ..\ -Filter *.inf -Recurse | Where {! ($_.FullName -like ('*\sign*'))} | Foreach-Object {
	#try {
    #        Write-Host "Considering copy-back of cat file associated with $_"
    #        if (Test-Path $_) {
	#        if ($_.BaseName.EndsWith('64')) {
    #                $catfile = (($_.BaseName.SubString(0, $_.BaseName.Length -2))+".cat")
    #            } else {
    #      	        $catfile = (($_.BaseName)+".cat")
    #            }
    #            $dest = (($_.DirectoryName)+"\"+($_.Basename)+".cat")
	#        Checked-Copy $catfile $dest
    #        }
    #    } catch {
    #         $failed = $true
	#     Write-Host "copyback on $_ failed"
    #    }
    #}
    #if ($failed) {
    #   throw "catfile copyback failed"
    #}
    #Write-Host "Copybacks done" 
    # copy back the sys files
    # TODO: is this needed?
    #$failed = $false
    #Get-ChildItem "..\build\$arch" -Filter *.sys | Foreach-Object {
    #    try {
    #        if (Test-Path $_) { 
    #             Checked-Copy $_ ($_.FullName)
    #        } 
    #    } catch { 
    #         $failed = $true
    #         Write-Host "copy back $_ failed with $_Exception.Message"
    #    }
    #}
    #if ($failed) {
    #    throw "copy back sys files failed"
    #}
    Checked-Copy xenvesa-display.dll ..\build\$arch\xenvesa-display.dll
    Pop-Location
}
