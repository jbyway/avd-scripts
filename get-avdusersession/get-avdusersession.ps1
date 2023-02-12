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
        if (!($context = (Get-AzContext))) {
            if ($SubscriptionId) {
                Write-Output "Attempting to connect to Azure Subscription $SubscriptionId"
                Connect-AzAccount -SubscriptionId $SubscriptionId  #Specific subscription context
                return ($SubscriptionId = ((Get-AzContext).Subscription.Id))
            }
            elseif ($SubscriptionId -and ($context.Subscription.Id -ne $SubscriptionId)) {
                Write-Output "Attempting to connect to Azure Subscription $SubscriptionId"
                Connect-AzAccount -SubscriptionId $SubscriptionId  #Specific subscription context
                return ($SubscriptionId = ((Get-AzContext).Subscription.Id))
            }
            else {
                Write-Output "Attempting to connect to Azure Subscription as default context"
                Connect-AzAccount  #Non specific context
                return ($SubscriptionId = ((Get-AzContext).Subscription.Id))
            }
        }
        else {
            Write-Host "Already connected to Azure Subscription"
            $context
        }
    }
    catch {
        Write-Error "Unable to connect to Azure Subscription $SubscriptionId"
        Write-Host "Error: [$($_.Exception.Message)]"
        break
    }
}


Function hello {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    Param(
        [Parameter(
            Mandatory = $false,
            HelpMessage = "here's sometext")]
        [switch]$first,
        #[string]$testing,
        [switch]$Force #you don't need to set this value
    )
    
    
    write-Output "string was $testing"
    if ($first.IsPresent -or $first) {
        Write-Host "Input was used $first"
        Write-Host $first
    }
    if ($PSCmdlet.ShouldProcess("Do you want to continue?", "Confirm")) {
        Write-Output "Continue is true"
    }
    Write-Host "Input was used $first"
}

# Function to check if a user is logged in
Function Get-UserSession {

    Param(
        [Parameter(
            Mandatory,
            HelpMessage = "Enter a valid UPN for the user")]
        [ValidatePattern('@avd.ms',
            ErrorMessage = "{0} is not a valid UPN try in format user@avd.ms")]
        [string]$userprincipalname,
        [Parameter(
            Mandatory=$false,
            HelpMessage = "Enter the resource group for the host pool"
        )]
        [string]$resourcegroupname,
  
        [Parameter(
            Mandatory=$false,
            HelpMessage = "Enter the host pool name"
        )]
        $hostpools,
        $SubscriptionId,
        [switch]$NoLogoffMessage, # If set to true then the user will be warned that their session is about to be logged off and a delay will be added to allow them to save their work
        [switch]$ForceLogoff, # If set to true then no confirmation dialogues will be shown
        [switch]$force)  # If set to true then the session will be forcibly logged off

    $UserName = @()
    
    # Get the list of all active sessions on the Azure Virtual Desktops
    # If the user is logged in, return the session information
   # if ((Get-AzWVDUserSession -ResourceGroupName $resourcegroupname -HostPoolName $hostpoolname).where({ $_.UserPrincipalName -match $userprincipalname }) | Select-Object SessionState, UserPrincipalName, CreateTime, @{ Name = 'SessionHost'; Expression = { $_.Name.Split('/')[1] } } , @{ Name = 'SessionID'; Expression = { $_.Name.Split('/')[2] } } -outvariable UserName) {
    
        #Single line text
        #  Write-Output "$($Username.UserPrincipalName) and is $(($UserName.SessionState).ToString().ToUpper()) on to the following session host: $(($UserName.Name).Split('/')[1]) with Session ID: $((($UserName.Name).Split('/')[2]))"
    
        # Table output
        #  write-output "$($Username | ft SessionState, UserPrincipalName, CreateTime, @{ Name='SessionHost'; Expression= {$_.Name.Split('/')[1]} } , @{ Name='SessionID'; Expression= {$_.Name.Split('/')[2]}} -Autosize)"
    
        # List output
        #Write-Output "$($Username | fl SessionState, UserPrincipalName, CreateTime, @{ Name='SessionHost'; Expression= {$_.Name.Split('/')[1]} } , @{ Name='SessionID'; Expression= {$_.Name.Split('/')[2]}})"
     
        Write-Output "The following session details were found for $userprincipalname"
        #write-output $UserName
        
    #    if (!$logoff) {
           ####### need to do work out what I ws doing here
     #   }
    #}
    $hostpools.Values | foreach-object {
        write-host "Checking hostpool: $($_.HostpoolName)"
        write-host "Checking resourcegroup: $($_.ResourceGroupName)"
        try {
            Get-AzWvdUserSession -HostPoolName $_.HostpoolName -ResourceGroupName $_.ResourceGroupName -SubscriptionId $SubscriptionId -filter "userprincipalname eq '$($userprincipalname)'" | foreach-object {
                Select-Object SessionState, UserPrincipalName, CreateTime, @{ Name = 'SessionHost'; Expression = { $_.Name.Split('/')[1] } }, 
                @{ Name = 'SessionID'; Expression = { $_.Name.Split('/')[2] } }, @{ Name = 'HostpoolName'; Expression = { $_.HostPoolName } } -OutVariable UserName
                Write-Output "The following session details were found for $userprincipalname"
                write-Output $UserName
            }
        }
        catch {
            write-host 'Error Occurred finding user sessions on $_.HostpoolName'
            write-host $_.Exception.Message
            SilentlyContinue
        }
    }
        
    # If the logoff switch is set to true then run the logoff function
    if ($logoff.IsPresent -and $logoff) {
        #If the logoff switch is set to true then run the logoff function
        Write-Output "Preparing to log user session off"
        $SessionId = $UserName.SessionID
        $sessionhost = $UserName.SessionHost
        LogOff-User -NoLogoffMessage $NoLogoffMessage -force $force -resourcegroupname $resourceGroupName -hostpoolname $hostpoolname -sessionhost $sessionhost -SessionId $SessionId
    }
    elseif (!$logoff) {
        # Else prompt the user to decide if they want to log the user off
        # If the logoff switch is not set to true then prompt the user to decide if they want to log the user off
        $logoffresponse = Get-UserResponse -question "Do you wish to log $userprincipalname off?"                
    } 
      
    if ($logoffresponse) {
        # If the user enters yes then run the logoff function
        Write-Output "Preparing to log user session off."
        $SessionId = $UserName.SessionID
        $sessionhost = $UserName.SessionHost
        LogOff-User -NoLogoffMessage $NoLogoffMessage -force $force -resourcegroupname $resourceGroupName -hostpoolname $hostpoolname -sessionhost $sessionhost -SessionId $SessionId
    }
    else {
        Write-Output "$userprincipalname will not be logged off. Exiting script"
        break
    }
}

else {
    write-output "No sessions found for $($userprincipalname)."
}


# Function to log off a user
Function LogOff-user {
    [CmdletBinding(SupportsShouldProcess)]
    Param(
        [Parameter(
            Mandatory = $false,
            HelpMessage = "Use this switch to force attempts to logoff users if you proceed")]
        [switch]$Force,
        [Parameter(
            Mandatory = $false,
            HelpMessage = "Use this switch to logoff users without prompting for confirmation")]
        [switch]$logoff,
        [Parameter(
            Mandatory = $false,
            HelpMessage = "Use this switch to warn users that their session is about to be logged off")]
        [switch]$NoLogoffMessage,    
        
        [int]$SessionId,    
        [string]$hostpoolname,
        [string]$resourcegroupname,
        [string]$sessionhost,
        [bool]$OfficeContainer = $false,
        [bool]$ProfileContainer = $false,
        [string]$delaylogoff = "5s" # use to delay the logoff of the user. This is useful if you want to warn the user before logging them off
    )
  
    #Check if the user should receive a warning prior to logging them off
    $NoLogoffMessage = Get-UserResponse -question "Do you wish to warn the user before logging them off?"

    # If the user is logged in, log them off
    If ($NoLogoffMessage) {
        try {
            Send-AzWvdUserSessionMessage -HostPoolName $hostpoolname -ResourceGroupName $resourcegroupname -UserSessionId $SessionId -SessionHostName $sessionhost -MessageBody "Your session will be disconnected in $delaylogoff. Please save your work." -MessageTitle "Logoff Warning"
            Write-Output "User Given 3 minute warning to logoff - Script will sleep for 3 minutes"
            Start-Sleep $delaylogoff #for now will set to 3mins change this prior or change to parameter and variable to be dynamic
        }
        catch {
            Write-Error "An error occurred when attempting to notify the user of the logoff, Do you wish to continue with the logoff anyway?"
            if ($ContinueLogoff) {
                Write-Output "Continuing with logoff"
                try {
                    Remove-AzWvdUserSession -HostPoolName $hostpoolname -ResourceGroupName $resourcegroupname -SessionHostName $sessionhost -Id $SessionId -force:$force
                }
                catch {
                    Write-output "There was an error logging the user off, the script will now quit"
                    Write-Host "Error: [$($_.Exception.Message)]"
                    break                
                }
            }
        }
    }
    
    Write-Output "Logging off User"
    try {
        Remove-AzWvdUserSession -HostPoolName $hostpoolname -ResourceGroupName $resourcegroupname -SessionHostName $sessionhost -Id $SessionId -force:$force
    }
    catch {
        Write-output "There was an error logging the user off, the script will now quit"
        Write-Host "Error: [$($_.Exception.Message)]"
        break
    }
    Write-Output "User logged off successfully."

    Start-Sleep 5s

  
    $response = Get-UserResponse -question "Do you wish to delete the user profile? Enter Y or N"

}

# Retrieve the list of host pools in the subscription and return the details in a hashtable
Function Get-AVDHostPools ($SubscriptionId) {
    

    $hostpools = @{}

    Get-AzWvdHostPool -SubscriptionId $SubscriptionId | ForEach-Object {
        $hostpool = @{
            SubscriptionId    = $_.Id.Split('/')[2]
            HostPoolName      = $_.Name
            ResourceGroupName = $_.Id.Split('/')[4]
        }
        $hostpools[$_.Name] = $hostpool
    }
    return $hostpools
}

function Get-UserResponse {
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
    Param(
        [int]$SessionId,    
        [string]$hostpoolname,
        [string]$resourcegroupname,
        [bool]$Force = $True,
        [bool]$NoLogoffMessage = $True,
        [string]$sessionhost,
        [bool]$OfficeContainer = $false,
        [bool]$ProfileContainer = $false
    )

    # Delete the user profile in the storage container file share
    if (Test-Path -Path (join-path -path "\\test" -ChildPath $Userprincipalname.split('@')[0] -AdditionalChildPath 'myfile.vhdx')) {
        Write-Output "User profile found"
        try {
            if ($ProfileContainer) { 
                Remove-Item -Path (join-path -path "\\test" -ChildPath $Userprincipalname.split('@')[0] -AdditionalChildPath 'myfile.vhdx') -Force
                Write-Output "User profile deleted successfully"
            }
            if ($OfficeContainer) {
                Remove-Item -Path (join-path -path "\\test" -ChildPath $Userprincipalname.split('@')[0] -AdditionalChildPath 'myfile.vhdx') -Force
                Write-Output "User profile deleted successfully"
            }
    
        }
        catch {
            Write-Output "There was an error deleting the user profile, the script will now quit"
            Write-Host "Error: [$($_.Exception.Message)]"
            break
        }
    }
    else {
        Write-Output "User profile not found"
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
if (!userprincipalname) {
    $userprincipalname = get-useraccount
}

if ((Get-AzContext).Subscription -ne $SubscriptionId) {
    $SubscriptionId = Login -SubscriptionId $SubscriptionId
}

if (!$hostpoolname) {
    # Get all hostpools if not passed in
    
}



# Check if the user is logged in only
Get-UserSession -userprincipalname $userprincipalname -resourcegroupname $resourceGroupName -hostpoolname $hostpoolname -force $true

#Run logoff manually if you want to set the parameters
LogOff-user -NoLogoffMessage $true -force $false -resourcegroupname $resourceGroupName -hostpoolname $hostpoolname -sessionhost $sessionhost -SessionId $SessionId



<#






# $hp = @{HostpoolName= $hostpools[8].Name; ResourceGroupName = $hostpools[8].Id.split('/')[4]; SubscriptionId= $hostpools[8].Id.split('/')[2]}

get-azwvdhostpool | select-object -property @{Name='SubscriptionId'; Expression= {$_.Id.split('/')[2]}}, @{Name='HostPoolName'; Expression= {$_.Name}}, @{Name='ResourceGroupName'; Expression= {$_.Id.split('/')[4]}} | Get-AzWvdUserSession -SubscriptionId {$_.SubscriptionId} -HostPoolName {$_HostPoolName} -ResourceGroupName {$_.ResourceGroupName}

$hostpools = @{

#$hp = get-azwvdhostpool | select-object -property @{Name='SubscriptionId'; Expression= {$_.Id.split('/')[2]}}, @{Name='HostPoolName'; Expression= {$_.Name}}, @{Name='ResourceGroupName'; Expression= {$_.Id.split('/')[4]}}

#>





$hostpools['hostpoolname'].ResourceGroupName



