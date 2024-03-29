[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [uri]$downloadUrl,
    [Parameter(Mandatory = $false)]
    [string]$tempFolderPath = (Join-Path $Env:SystemDrive "tempWindows11InstallMedia"),
    [Parameter(Mandatory = $false)]
    $quiet = $false,
    [Parameter(Mandatory = $false)]
    $SkipFinalize = $false,
    [Parameter(Mandatory = $false)]
    $Finalize = $false,
    [Parameter(Mandatory = $false)]
    $ScanOnly = $false,
    [Parameter(Mandatory = $false)]
    $dynamicUpdate = $false,
    [Parameter(Mandatory = $false)]
    [uri]$pstoolsdownloadurl,
    [Parameter(Mandatory = $false)]
    $upgradenow = $false,
    [Parameter(Mandatory = $false)]
    $useproxy = $false,
    [Parameter(Mandatory = $false)]
    $force = $false
)

function Get-WindowsUpdateMedia
(
    [Parameter(Mandatory = $true)]
    [uri]$downloadUrl,
    [Parameter(Mandatory = $false)]
    [string]$tempFolderPath = (Join-Path $Env:SystemDrive "tempWindows11InstallMedia"),
    [Parameter(Mandatory = $false)]
    [uri]$pstoolsdownloadurl,
    [Parameter(Mandatory = $false)]
    [bool]$useproxy = $false
) {
    Begin {

        $mountedmedia = Join-Path $tempFolderPath "mountedmedia"
        $install = Join-Path $tempFolderPath "install"

        #Create temp folder if it doesn't already exist
        if (!(Test-Path -path $install)) {
            New-Item -Path $tempFolderPath -ItemType Directory -Force | Out-Null
            New-Item -Path $mountedmedia -ItemType Directory -Force | Out-Null
            New-Item -Path $install -ItemType Directory -Force | Out-Null
        }
        Write-Output "Temporary Media Location: $mountedmedia"
        Write-Output "Temporary Install Media Path: $install"
        write-output "Download URL: $downloadUrl"
        write-output "PSTools Download URL: $pstoolsdownloadurl"
        # Create the download file path using the last segment of the download URL and the temp folder path
        $downloadFile = join-path $tempFolderPath $downloadurl.segments[-1]

        # create the web client object for public download and download file this will be used to download the file quickly
        $webclient = New-Object Net.WebClient

        # If proxy is required then leave the proxy address as default otherwise set to default
        if ($useproxy) {
            $webclient.Proxy = [System.Net.WebRequest]::GetSystemWebProxy()
            $webclient.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials
        }
        else {
            $webclient.Proxy = $null
        }
    }
    Process {

    
        try {
        
            # Download the file    
            $webclient.DownloadFile($downloadUrl, $downloadFile)

        }
        catch {
            Write-Output "Error downloading file"
            Write-Output $_.Exception.Message
        }
        
        try {
            #Download PSExec
            
            $webclient.DownloadFile($pstoolsdownloadurl, $tempFolderPath + "\PSTools.zip")
        }
        catch {
            Write-Output "Error downloading file"
            Write-Output $_.Exception.Message
        }

        try {
            #Extract PSExec
            Expand-Archive -Path ($tempFolderPath + "\PSTools.zip") -DestinationPath ($tempFolderPath + "\PSTools") -Force
        }
        catch {
            Write-Output "Error extracting file"
            Write-Output $_.Exception.Message
        }

        # Mount the VHDX and obtain drive letter then copy contents to local temp folder not using the drive letter as it may not be the same on all systems
        $mountedvhd = Mount-DiskImage -ImagePath $downloadFile -NoDriveLetter -Access ReadOnly -PassThru | Get-Disk | Get-Partition

        $mountedvhd[1] | Add-PartitionAccessPath -AccessPath $mountedmedia
        
        xcopy $mountedmedia $install /siehy

    }
    End {
        # Dismount the VHDX this should happen prior to the start of the setup.exe
        $mountedvhd[1] | Remove-PartitionAccessPath -AccessPath $mountedmedia
        Dismount-DiskImage -ImagePath $downloadFile
    
        # clean up the web client object
        $webclient.dispose()
    }
}

function test-windowssetup 
(
    [Parameter(Mandatory = $false)]
    [string]$tempFolderPath = (Join-Path $Env:SystemDrive  "tempWindows11InstallMedia"),
    [Parameter(Mandatory = $false)]
    [uri]$downloadUrl,
    [Parameter(Mandatory = $false)]
    [string]$argumentList,
    [Parameter(Mandatory = $false)]
    [uri]$pstoolsdownloadurl,
    [Parameter(Mandatory = $false)]
    [bool]$useproxy
) {

    #Create temp folder if it doesn't already exist
    $setupPath = Join-Path $tempfolderPath "install\setup.exe"
    if (!(Test-Path -path ($setupPath = (Join-Path $tempfolderPath "install\setup.exe")))) {
          Get-WindowsUpdateMedia -downloadUrl $downloadUrl -pstoolsdownloadurl $pstoolsdownloadurl -tempFolderPath $tempFolderPath -useproxy $useproxy
    }

    # Get the setup.exe path
    

    # Run the setup verification
    Write-Output "Running setup verification"

    $process = (start-process $setupPath -ArgumentList $argumentList -Wait -PassThru)

    '0x{0:x}' -f $process.ExitCode

    # Check the exit code
    switch ($process.ExitCode) {
        '-1047526896' {
            Write-Output "No issues found" -OutVariable scanonlymessage
        }
        '-1047526904' {
            Write-Output "Compatibility issues found (hard block)" -OutVariable scanonlymessage
        }
        '-1047526908' {
            Write-Output "Migration choice (auto upgrade) not available (probably the wrong SKU or architecture)" -OutVariable scanonlymessage
        }
        '-1047526911' {
            Write-Output "Does not meet system requirements for Windows 11" -OutVariable scanonlymessage
        }
        '-1047526898' {
            Write-Output "Insufficient free disk space to perform upgrade" -OutVariable scanonlymessage
        }
        '-1047526912'{
            Write-Output "Windows 11 is not available on this device - missing TPM2.0, enable Trusted Launch on VM first" -OutVariable scanonlymessage
        }
        Default {
            Write-Output "Unknown outcome - check the log files and confirm before running again with `$force = `$true parameter" -OutVariable scanonlymessage
        }
    }
    Write-Output $scanonlymessage

}

function get-windowsupgradescanresult ($process) {
    
    # Get the scan only result code
    'Windows Setup Scan Result: 0x{0:x}' -f $process 


    # Check the exit code
    switch ($process) {
        '-1047526896' {
            Write-Output "No issues found" -OutVariable scanonlymessage
        }
        '-1047526904' {
            Write-Output "Compatibility issues found (hard block)" -OutVariable scanonlymessage
        }
        '-1047526908' {
            Write-Output "Migration choice (auto upgrade) not available (probably the wrong SKU or architecture)" -OutVariable scanonlymessage
        }
        '-1047526911' {
            Write-Output "Does not meet system requirements for Windows 11" -OutVariable scanonlymessage
        }
        '-1047526898' {
            Write-Output "Insufficient free disk space to perform upgrade" -OutVariable scanonlymessage
        }
        '-1047526912'{
            Write-Output "Does not meet system requirements for Windows 11 - missing TPM2.0, enable Trusted Launch on VM first" -OutVariable scanonlymessage
        }
        Default {
            Write-Output "Unknown outcome - check the log files and confirm before running again with `$force = `$true parameter" -OutVariable scanonlymessage
        }
    }
    
    #Save the result to a file
    (Get-Date -Format "yyyyMMddHHmm") + ' - Windows Setup Scanonly Result Code: 0x{0:x}' -f $process + ' - ' + $scanonlymessage | out-file $tempFolderPath\scanonlyresult.txt



}


function start-windowssetup 
(
    [Parameter(Mandatory = $false)]
    [string]$tempFolderPath = (Join-Path $Env:SystemDrive "tempWindows11InstallMedia"),
    [Parameter(Mandatory = $false)]
    [uri]$downloadUrl,
    [Parameter(Mandatory = $false)]
    [bool]$quiet,
    [Parameter(Mandatory = $false)]
    [bool]$SkipFinalize,
    [Parameter(Mandatory = $false)]
    [bool]$Finalize,
    [Parameter(Mandatory = $false)]
    [bool]$ScanOnly,
    [Parameter(Mandatory = $false)]
    [bool]$dynamicUpdate,
    [Parameter(Mandatory = $false)]
    [bool]$upgradenow,
    [Parameter(Mandatory = $false)]
    [uri]$pstoolsdownloadurl,
    [Parameter(Mandatory = $false)]
    [bool]$useproxy,
    [Parameter(Mandatory = $false)]
    [bool]$force = $false
) {
    $setuplogs = Join-Path $tempFolderPath "setuplogs"
    # Create the argument list for setup based on the parameters passed to the function
    $argumentList = "/auto upgrade /showoobe none /eula accept $(if ($dynamicUpdate) { "/dynamicupdate enable" } else { "/dynamicupdate disable"}) $(if ($SkipFinalize) { "/skipfinalize" }) $(if ($Finalize) { "/finalize" }) $(if ($ScanOnly) { "/compat scanonly" }) /copylogs $setuplogs $(if ($quiet) { "/quiet" })"

    write-output $argumentList
    
    # Check for download media and download if not found
    $setupPath = Join-Path $tempfolderPath "install\setup.exe"
    if (!(Test-Path -path ($setupPath = (Join-Path $tempfolderPath "install\setup.exe")))) {
        Get-WindowsUpdateMedia -downloadUrl $downloadUrl -pstoolsdownloadurl $pstoolsdownloadurl -useproxy $useproxy
    }
    
    # Check if user is logged in and perform silently if not otherwise run interactively if not set to use quiet switch
    if (!($sessionId = (get-process explorer -ErrorAction SilentlyContinue).SessionId)) {
        $sessionId = 0
        $quiet = $true # Force quiet mode if no user logged in
    }

    if ($ScanOnly) {
        # Run the setup verification
        Write-Output "Running setup verification"

        #Psexec to allow interaction with user session check for explorer process and get the session id otherwise return 0 for console
        $process = start-process -FilePath $tempFolderPath\PSTools\psexec.exe -ArgumentList "-accepteula -nobanner -h -i $($sessionId) $($setupPath) $($argumentList)" -Wait -PassThru -WindowStyle Hidden

        # Get the scan only result code and write to the log file
        get-windowsupgradescanresult $process.ExitCode 
        Write-Output "Completed upgrade scan - check logs for results"
        Write-Output "Setup scan exit code: $($process.ExitCode)"
        
        # Good scan result = 0xc1900210 however other results may still allow upgrade so you can attempt to run with force option once confirmed
    }
    elseif ($upgradenow) {
        if (Test-Path -path (Join-Path $tempfolderPath "scanonlyresult.txt")) {
            if (((Get-Content $tempfolderPath\scanonlyresult.txt) -match "No issues found") -or $force ) {  # Check for issues and if none found then run setup, or if $force = $true then do it anyway
                Write-Output "Windows Upgrade is about to begin..."
                set-windowssetupcleanuptask

                # If no issues found in previous scan then run the update or if set to $force then also run upgrade
                # Psexec to allow interaction with user session check for explorer process and get the session id otherwise return 0 for console ($quiet -eq $false -and $sessionId -ne 0)
                $process = start-process -FilePath $tempFolderPath\PSTools\psexec.exe -ArgumentList "-accepteula -nobanner -h -i $($sessionId) $($setupPath) $($argumentList)" -Wait:$upgradenow -PassThru -WindowStyle Hidden
            }
            else {
                Write-Output "Issues found - check the log file"
                Exit
            }             
        }
        else {
            Write-Output "No scanonlyresult.txt file found - will continue with upgrade"
            
            # Create task to delete the temp media after 5 days
            set-windowssetupcleanuptask
            
            #Psexec to allow interaction with user session
             
            $process = start-process -FilePath $tempFolderPath\PSTools\psexec.exe -ArgumentList "-accepteula -nobanner -h -i $($sessionId) $($setupPath) $($argumentList)" -Wait:$upgradenow -PassThru
        }
    }
    else {
        Write-Output "No action was taken - run with either `$scanonly or `$upgradenow set to `$true"
    }
}

function set-windowssetupcleanuptask 
( 
    [Parameter(Mandatory = $false)]
    [string]$tempFolderPath = ($Env:SystemDrive + "\tempWindows11InstallMedia")
)    
{
    #Clean up the temp folder
    
    $action = New-ScheduledTaskAction -execute "powershell.exe" -Argument "-NoProfile -WindowStyle Hidden -command `"& { Remove-Item -Path $tempFolderPath -Force -Recurse }`""
    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddDays(5)
    $principal = New-ScheduledTaskPrincipal -UserId "LOCALSERVICE" -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 10)
    $task = New-ScheduledTask -Action $action -Trigger $trigger -Principal $principal -Settings $settings
    Register-ScheduledTask -TaskName "Cleanup Windows Update Media" -InputObject $task -Force
}


# Run the script
start-windowssetup -downloadUrl $downloadUrl -quiet $quiet.ToBoolean($_) -SkipFinalize $SkipFinalize.ToBoolean($_) -Finalize $Finalize.ToBoolean($_) -ScanOnly $ScanOnly.ToBoolean($_) -dynamicUpdate $dynamicUpdate.ToBoolean($_) -pstoolsdownloadurl $pstoolsdownloadurl -upgradenow $upgradenow.ToBoolean($_) -useproxy $useproxy.ToBoolean($_) -force $force.ToBoolean($_)


