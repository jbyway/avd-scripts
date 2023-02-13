<# .SYNOPSIS 
    Function to check if a user is logged in to AVD, remotely log them off and enable deletion of their profile disk. 
    .DESCRIPTION
    Function to check if a user is logged in and if so return the session information and prompt to log off the user`
    and offer the ability to delete their FSLogix profile once logged off. 
    .EXAMPLE
    Get-UserSession -userprincipalname
#>

[CmdletBinding(SupportsShouldProcess)]
Param (
    [Parameter(Position = 0, Mandatory = $false, HelpMessage = "Enter username in valid UPN format")]
    [ValidatePattern('@avd.ms', ErrorMessage = "{0} is not a valid UPN try in format user@domain.com")]
    [string]$userprincipalname, # Enter the UserPrincipal name of the user you wish to search for ie user@contoso.com
    [Parameter(Mandatory = $false, HelpMessage = "Enter the resource group for the host pool or leave 
        empty to return all known host pool environments")]
    [string]$resourcegroupname, #Specify the resource group name you wish to search
    [Parameter(Mandatory = $false, HelpMessage = "Enter the resource group for the host pool you 
        wish to target or leave empty to return all known host pool environments")]
    [string]$hostpoolname, # Specify the host pool name you wish to search
    [Parameter(Mandatory = $false, HelpMessage = "Enter the Azure SubscriptionId you to wish to login to")]
    [guid]$SubscriptionId, # Azure Subscription ID you wish to login to
    $UserSession = $null,
    [switch]$Force, # Alternate to Confirm switch to not confirm user input and default actions
    [switch]$ForceLogoff, # Use this switch to logoff users in the event of a stuck session
    [switch]$NoLogoffMessage # Use this switch to silently log off users without a warning message"
)

# Handle for users who don't want to be prompted for input and may use Force switch instead of Confirm
if ($Force -and -not $Confirm) {
    $ConfirmPreference = 'None'
}

#Check if logged into Azure Subscription already and if not then prompt to authenticate, accept a subscriptionId
function Login {
    [CmdletBinding(SupportsShouldProcess)]
    Param(
        $SubscriptionId
    )
    try {
        if (!($context = (Get-AzContext).Subscription.Id)) {
            if ($SubscriptionId) {
                write-host "Attempting to connect to Azure Subscription $SubscriptionId"
                Connect-AzAccount -SubscriptionId $SubscriptionId  #Specific subscription context
                return ($SubscriptionId = ((Get-AzContext).Subscription.Id))
            }
            elseif ($SubscriptionId -and ($context.Subscription.Id -ne $SubscriptionId)) {
                write-host "Attempting to connect to Azure Subscription $SubscriptionId"
                Connect-AzAccount -SubscriptionId $SubscriptionId  #Specific subscription context
                return ($SubscriptionId = ((Get-AzContext).Subscription.Id))
            }
            else {
                write-host "Attempting to connect to Azure Subscription as default context"
                Connect-AzAccount  #Non specific context
                return ($SubscriptionId = ((Get-AzContext).Subscription.Id))
            }
        }
        else {
            Write-Host "Already connected to Azure Subscription"
            return $context
        }
    }
    catch {
        Write-Error "Unable to connect to Azure Subscription $SubscriptionId"
        Write-Host "Error: [$($_.Exception.Message)]"
        break
    }
}


# Function to check if a user is logged in
Function Get-UserSession {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Low')]
    Param(
        [Parameter(
            Mandatory,
            HelpMessage = "Enter a valid UPN for the user")]
        [ValidatePattern('@avd.ms',
            ErrorMessage = "{0} is not a valid UPN try in format user@avd.ms")]
        [string]$userprincipalname,
        [Parameter(
            Mandatory = $false,
            HelpMessage = "Enter the resource group for the host pool"
        )]
        [string]$resourcegroupname,
  
        [Parameter(
            Mandatory = $false,
            HelpMessage = "Enter the host pool name"
        )]
        $hostpools,
        $SubscriptionId,
        [switch]$NoLogoffMessage, # If set to true then the user will be warned that their session is about to be logged off and a delay will be added to allow them to save their work
        [switch]$ForceLogoff, # If set to true then no confirmation dialogues will be shown
        [switch]$force)  # If set to true then the session will be forcibly logged off

    $UserName = @()
    $SessionDetails = @()
    $i = 1
    
    $hostpools.Values | foreach-object {
        write-host -NoNewline "Checking hostpool: $($_.HostpoolName)..."
        #write-host "Checking resourcegroup: $($_.ResourceGroupName)"
        try {
            $Sessions = Get-AzWvdUserSession -HostPoolName $_.HostpoolName -ResourceGroupName $_.ResourceGroupName -SubscriptionId $SubscriptionId -filter "userprincipalname eq '$($userprincipalname)'" 
            if ($Sessions) { 
                $SessionDetails += $Sessions | Select-Object SessionState, UserPrincipalName, CreateTime,
                @{ Name = 'SessionHost'; Expression = { $_.Name.Split('/')[1] } },
                @{ Name = 'SessionID'; Expression = { $_.Name.Split('/')[2] } },
                @{ Name = 'HostpoolName'; Expression = { $_.Name.Split('/')[0] } },
                @{ Name = 'ResourceGroupName'; Expression = { $_.Id.Split('/')[4] } },
                @{ Name = 'SubscriptionId'; Expression = { $_.Id.Split('/')[2] } },
                @{ Name = 'Index'; Expression = { $i } } #Index for easy reference in the logoff function
                $i++
                Write-Host "Found $($Sessions.Count) session(s)"
            }
            else {
                Write-Host "No sessions found."
            }
        }
        catch {
            write-host 'Error Occurred finding user sessions on $_.HostpoolName'
            write-host $_.Exception.Message -ErrorAction SilentlyContinue
        }    
    }
        
    if ($SessionDetails) {
        
        return $SessionDetails
    }
    else {
        write-host "No sessions found for $userprincipalname"
        break
    }
    
}



# Function to log off a user
Function LogOff-user {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    Param(
        [Parameter(
            Mandatory = $false,
            HelpMessage = "Use this switch to force attempts to logoff users if you proceed")]
        [switch]$Force,
        [Parameter(
            Mandatory = $false,
            HelpMessage = "Use this switch to warn users that their session is about to be logged off")]
        [switch]$NoLogoffMessage,
        [switch]$ForceLogoff,   
        [array]$SessionDetails,
        [string]$delaylogoff = "5s" # use to delay the logoff of the user. This is useful if you want to warn the user before logging them off
    )
  
    #Check if the user should receive a warning prior to logging them off
    #$NoLogoffMessage = Get-UserResponse -question "Do you wish to warn the user before logging them off?"

    # If the user is logged in, log them off
    Write-host "Preparing to log off the following sessions for $($SessionDetails[0].UserPrincipalName):"
    $SessionDetails | ft * -Autosize

    if (!$NoLogoffMessage.IsPresent -and !$NoLogoffMessage.Value) {
        $SessionDetails | foreach-object {
            Send-AzWvdUserSessionMessage -HostPoolName $_.hostpoolname -ResourceGroupName $_.resourcegroupname -UserSessionId $_.SessionId -SessionHostName $_.sessionhost -MessageBody "Your session will be logged off in $delaylogoff. Please save your work." -MessageTitle "Logoff Warning"
            write-host "User Given $delaylogoff warning to logoff - Script will sleep for $delaylogoff"
        }
        Start-Sleep $delaylogoff #for now will set to 3mins change this prior or change to parameter and variable to be dynamic
    }

    $SessionDetails | Foreach-object {
        try {
            #$logofftarget = Get-AzWvdUserSession -HostPoolName $_.hostpoolname -ResourceGroupName $_.resourcegroupname -SessionHostName $_.sessionhost -Id $_.SessionId
            $logofftarget = "Hostpool: $($_.Hostpoolname) || SessionHost: $($_.SessionHost) || SessionID: $($_.SessionID)"
            if ($PSCmdlet.ShouldProcess($logofftarget, "Logoff user")) {

                Remove-AzWvdUserSession -HostPoolName $_.hostpoolname -ResourceGroupName $_.resourcegroupname -SessionHostName $_.sessionhost -Id $_.SessionId -force:$force
                write-host "User logged off successfully."    
            }
            
        }
        catch {
            write-host "There was an error logging the user off, the script will now quit"
            Write-Host "Error: [$($_.Exception.Message)]"
            break
        }
    }
    

    Start-Sleep 5s

  
    #$response = Get-UserResponse -question "Do you wish to delete the user profile? Enter Y or N"

}

# Retrieve the list of host pools in the subscription and return the details in a hashtable
Function Get-AVDHostPools ($SubscriptionId) {
    

    $hostpools = @{}
    Write-Host "Retrieving host pool details..."
    Get-AzWvdHostPool -SubscriptionId $SubscriptionId | ForEach-Object {
        $hostpool = @{
            SubscriptionId    = $_.Id.Split('/')[2]
            HostPoolName      = $_.Name
            ResourceGroupName = $_.Id.Split('/')[4]
        }
        $hostpools[$_.Name] = $hostpool
        Write-Host "Found host pool: $($_.Name)..."
    }
    return $hostpools
}

function Get-UserResponse { #Not currently in use
    Param(
        [string]$response,
        [string]$question
    )
    write-host $question | Out-Null
    do {
        $response = Read-Host "Enter Y or N"
        if ($response -eq "Y" -or $response -eq "yes") {
            return $true
        }
        elseif ($response -eq "N" -or $response -eq "no") {
            return $false
        }
        else {
            Write-Host "Please enter a valid response!" | Out-Null
        }
    }
    while ($response -ne "y" -and $response -ne "n" -and $response -ne "yes" -and $response -ne "no")
}

# Function to delete the user profile
function Delete-Profile {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    Param(
        
        [string]$UserprincipalName,
        [string]$ProfileSharePath = "c:\temptemp\" #Change this to match your profile share path
    )

    # Delete the user profile in the storage container file share you will need to change the path to match (likely just path to the file share)
    $userprofilepath = join-path -path $ProfileSharePath -ChildPath "$($UserprincipalName.split('@')[0])*\"
    if (test-path($userprofilepath)) { #Check the share and see if files exist
        write-host "User profile found"
        try {
            $readydelete = Get-ChildItem -Path $userprofilepath -Recurse
            $readydelete | foreach-object {
            if ($PSCmdlet.ShouldProcess($_, "Delete user profile")) {
                Remove-Item -Path $_ -Recurse -Force:$Force
                write-host "User profile deleted successfully"
            }
        }
    
        }
        catch {
            write-host "There was an error deleting the user profile, the script will now quit"
            Write-Host "Error: [$($_.Exception.Message)]"
            break
        }
    }
    else {
        write-host "User profile not found"
    }


}

function get-useraccount {
    # Get the userprincipalname for the user if not passed in
    if (!$userprincipalname) {
        $userprincipalname = Read-Host "Enter the user principal name"
        if (!($userprincipalname -match "(\@avd.ms$)")) {
            # Validate the UPN is in the correct format and error out if not
            $formatError = New-Object System.FormatException
            throw  $formatError, "`n$userprincipalname was an invalid UPN, rerun the script and check the UPN format is valid"
        }
    }
    return $userprincipalname
}

# Get the user principal name if not passed in
if (!$userprincipalname) {
    $userprincipalname = get-useraccount
}

# Get the subscription ID if not passed in
if ((Get-AzContext).Subscription -ne $SubscriptionId) {
    $SubscriptionId = Login -SubscriptionId $SubscriptionId
}

#Get Hostpools
$hostpools = Get-AVDHostPools -SubscriptionId $SubscriptionId
write-host "Found $($hostpools.Count) host pools in the subscription"

#Get User sessions
$SessionDetails = Get-UserSession -userprincipalname $userprincipalname -hostpools $hostpools

#Get which session would like to logoff
Write-Host "Which session would you like to logoff?"
$SessionDetails | ft Index, HostpoolName, SessionId, SessionState, CreateTime, SessionHost -AutoSize
$selectedindexes = Read-Host "Enter the index values separated by a comma or leave empty for all sessions (e.g. 1, 2, 3)"
$selectedIndexes = $selectedIndexes.Split(",") | ForEach-Object { $_.Trim() }
$selectedsession = @()
if ($selectedindexes -eq "") {
    foreach ($selectedindexvalue in $selectedindexes) {
        $selectedsession +=  $SessionDetails | select-object | where-object { $_.Index -eq $selectedindexvalue }
        Logoff-user -SessionDetails $selectedsession
    }
}
else {
    Logoff-User -SessionDetails $SessionDetails
}

#Delete the user profile

Delete-Profile -UserprincipalName $userprincipalname






#start the script


#Get-UserSession -userprincipalname $userprincipalname -resourcegroupname $resourceGroupName -hostpoolname $hostpoolname -force $true

#Run logoff manually if you want to set the parameters
#LogOff-user -NoLogoffMessage $true -force $false -resourcegroupname $resourceGroupName -hostpoolname $hostpoolname -sessionhost $sessionhost -SessionId $SessionId











