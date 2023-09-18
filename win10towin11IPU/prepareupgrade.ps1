[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [uri]$downloadUrl,
    [Parameter(Mandatory = $false)]
    [string]$tempFolderPath = ($Env:SystemDrive + "\tempWindows11InstallMedia"),
    [Parameter(Mandatory = $false)]
    [switch]$quiet,
    [Parameter(ParameterSetName = 'SkipFinalize', Mandatory)]
    [switch]$SkipFinalize,
    [Parameter(ParameterSetName = 'Finalize', Mandatory)]
    [switch]$Finalize,
    [Parameter(ParameterSetName = 'ScanOnly', Mandatory)]
    [switch]$ScanOnly,
    [Parameter(Mandatory = $false)]
    [switch]$dynamicUpdate
)

function Get-WindowsUpdateMedia
(
    [Parameter(Mandatory = $false)]
    [uri]$downloadUrl,
    [Parameter(Mandatory = $false)]
    [string]$tempFolderPath = ($Env:SystemDrive + "\tempWindows11InstallMedia")
) {
    Begin {

        #Create temp folder if it doesn't already exist
        if (!(Test-Path -path $tempFolderPath)) {
            New-Item -Path $tempFolderPath -ItemType Directory -Force | Out-Null
            $mountedmedia = New-Item -Path $tempFolderPath\mountedmedia -ItemType Directory -Force
            $install = New-Item -Path $tempFolderPath\install -ItemType Directory -Force
        }

        # Create the download file path using the last segment of the download URL and the temp folder path
        $downloadFile = join-path $tempFolderPath $downloadurl.segments[-1]

        # create the web client object for public download and download file this will be used to download the file quickly
        $webclient = New-Object Net.WebClient
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
    [string]$tempFolderPath = ($Env:SystemDrive + "\tempWindows11InstallMedia"),
    [Parameter(Mandatory = $false)]
    [uri]$downloadUrl,
    [Parameter(Mandatory = $false)]
    [string]$argumentList
) {

    #Create temp folder if it doesn't already exist
    $setupPath = Join-Path $tempfolderPath "install\setup.exe"
    if (!(Test-Path -path ($setupPath = (Join-Path $tempfolderPath "install\setup.exe")))) {
        #  Get-WindowsUpdateMedia -downloadUrl $downloadUrl
        write-output "hi"
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
        '-1047526912' {
            Write-Output "Does not meet system requirements for Windows 11" -OutVariable scanonlymessage
        }
        '-1047526898' {
            Write-Output "Insufficient free disk space to perform upgrade" -OutVariable scanonlymessage
        }
        Default {
            Write-Output "Unknown outcome - check the log file" -OutVariable scanonlymessage
        }
    }
    Write-Output $scanonlymessage

}

function get-windowsupdateresult ($process) {
    

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
        '-1047526912' {
            Write-Output "Does not meet system requirements for Windows 11" -OutVariable scanonlymessage
        }
        '-1047526898' {
            Write-Output "Insufficient free disk space to perform upgrade" -OutVariable scanonlymessage
        }
        Default {
            Write-Output "Unknown outcome - check the log file" -OutVariable scanonlymessage
        }
    }
    
    #Save the result to a file
    (Get-Date -Format "yyyyMMddHHmm") + ' - Windows Setup Scanonly Result Code: 0x{0:x}' -f $process + ' - ' + $scanonlymessage | out-file $tempFolderPath\scanonlyresult.txt



}


function start-windowssetup 
(
    [Parameter(Mandatory = $false)]
    [string]$tempFolderPath = ($Env:SystemDrive + "\tempWindows11InstallMedia"),
    [Parameter(Mandatory = $false)]
    [uri]$downloadUrl,
    [Parameter(Mandatory = $false)]
    [switch]$quiet,
    [Parameter(Mandatory = $false)]
    [switch]$SkipFinalize,
    [Parameter(Mandatory = $false)]
    [switch]$Finalize,
    [Parameter(Mandatory = $false)]
    [switch]$ScanOnly,
    [Parameter(Mandatory = $false)]
    [switch]$dynamicUpdate
) {

    $argumentList = "/auto upgrade /eula accept $(if ($dynamicUpdate) { "/dynamicupdate enable" } else { "/dynamicupdate disable"}) $(if ($SkipFinalize) { "/skipfinalize" }) $(if ($Finalize) { "/finalize" }) $(if ($ScanOnly) { "/compat scanonly" }) /copylogs $($tempFolderPath)\setuplogs $(if ($quiet) { "/quiet" })"


    # Check for download media and download if not found
    $setupPath = Join-Path $tempfolderPath "install\setup.exe"
    if (!(Test-Path -path ($setupPath = (Join-Path $tempfolderPath "install\setup.exe")))) {
        Get-WindowsUpdateMedia -downloadUrl $downloadUrl
         
    }

    if ($ScanOnly) {
        # Run the setup verification
        Write-Output "Running setup verification"

        $process = (start-process $setupPath -ArgumentList $argumentList -Wait -PassThru)
        get-windowsupdateresult $process.ExitCode 
        write-output $process.ExitCode
        # Good scan result = 0xc1900210
    }
    else {
        if (Test-Path -path (Join-Path $tempfolderPath "scanonlyresult.txt")) {
            if ((Get-Content $tempfolderPath\scanonlyresult.txt) -match "No issues found") {
                Write-Output "No issues found"
                # If no issues found in previous scan then run the update
                start-process $setupPath -ArgumentList $argumentlist -PassThru
            }
            else {
                Write-Output "Issues found - check the log file"
                Exit
            }             
        }
        else {
            Write-Output "No scanonlyresult.txt file found - will continue with upgrade"
            
            # Create task to delete the temp media after 5 days
            set-windowsmediacleanuptask
            
            # Run the setup
            start-process $setupPath -ArgumentList $argumentlist -PassThru
        }
    }
}

function set-windowsmediacleanuptask 
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
#Clean up the temp folder
# Remove-Item -Path $tempFolder -Force -Recurse

# Run the script
start-windowssetup -downloadUrl $downloadUrl -quiet:$quiet -SkipFinalize:$SkipFinalize -Finalize:$Finalize -ScanOnly:$ScanOnly -dynamicUpdate:$dynamicUpdate