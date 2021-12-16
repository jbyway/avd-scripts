

# Determines the current MSRDC processes and returns any active AVD Gateway IPs and the Process ID of the MSRDC Client
function get-avdconnectionstats {
    #Not implemented
    [cmdletbinding()]
    Param(
        [bool]$GenerateHTMLReport = $true,
        [switch]$ExtendedTest,
        [string]$avdgwenvironment = 'wvd' # allow for multiple Azure cloud environments
    )

    $avdgwip = get-avdgwip
    $avdgwapi = get-avdgwapi -avdgwip $avdgwip[0] -avdgwenvironment $avdgwenvironment


}


function get-avdgwip {
    [cmdletbinding()]
    Param()
   
    # Get Process ID of MSRDC and IP address of the AVD Gateway in use by any sessions
    Write-Host "[Discovering current MSRD Process ID]" -ForegroundColor Green
    if (-not(Get-Process -Name msrdc).id) {
        # No MSRDC Client process found terminate script
        Write-Host "No active MSRDC process detected... exiting script" -ForegroundColor Red
        exit 1
    }
    else {
        $msrdcpid = (Get-Process -Name msrdc).id
        $msrdcpid | ForEach-Object { Write-Host "MSRDC Client Process ID: $_ `r`n" -ForegroundColor Green }  
    }
       
    if (-not((Get-NetTCPConnection -OwningProcess (Get-Process -Name msrdc).id -state Established -ErrorAction Continue) | select-object -Property RemoteAddress -Unique)) {
        Write-Error "No active connections found for MSRDC - exiting script"
        exit 1
    }
    else {
        $avdgwip = (Get-NetTCPConnection -OwningProcess (Get-Process -Name msrdc).id -state Established -ErrorAction Continue).RemoteAddress | select-Object <#-Property RemoteAddress#> -Unique
        Write-Host "[MSRDC Established TCP Connections]`r" -ForegroundColor Green
        $avdgwip | foreach-object { "Remote IP: " + $_ + "`r" | Write-Host -ForegroundColor Green }
    
    }
    
    return $avdgwip

}

# Queries the AVD Gateway API health endpoint for the specified AVD Gateway IP and returns the response
function get-avdgwapi {
    [CmdletBinding()]Param(
        [Parameter(Mandatory = $true)]
        [array]$avdgwip,
        [string]$avdgwenvironment = "wvd"
    )
    
    foreach ($remoteaddress in $avdgwip) {
        Invoke-WebRequest  -Uri ('https://' + $remoteaddress + '/api/health') -Headers @{Host = "rdgateway.$avdgwenvironment.microsoft.com" } | foreach-object {
            if ($_.StatusCode -eq 200) {
                #((Invoke-WebRequest  -Uri ('https://' + $remoteaddress + '/api/health') -Headers @{Host = "rdgateway.$avdgwenvironment.microsoft.com" }).StatusCode -eq 200) {
                
                [PSCustomObject]@{
                    RemoteAddress = $remoteaddress
                    AVDRegionCode = [string]$_.Headers.'x-ms-wvd-service-region'
                    Content       = [object]$_.Content
                    RegionURL     = [string](ConvertFrom-Json ($_.Content)).RegionUrl
                }
                    
            }
            else {
                Write-Host ($remoteaddress).Trim()' does not appear to be a valid AVD Gateway IP. Skipping...' -foregroundcolor Yellow
            }
        }
    }
}

# Tests each IP from the MSRDC process and determines if a valid AVD Gateway or not and returns each result. Temporary solution to test multiple AVD Gateways. 
function test-avdgwapi {
    #not implemented
    Param(
        [Object]$avdgwip
    )
    $ErrorActionPreference = 'SilentlyContinue'
    Invoke-WebRequest  -Uri ('https://' + $avdgwip + '/api/health') -Headers @{Host = "rdgateway.wvd.microsoft.com" } -SkipHttpErrorCheck -ErrorAction Continue
}

# Provides the call to the test-avdgwapi function and returns the results using the IPs of each connection by the MSRDC process - temporary function
function get-avdgwapichoice {
    #Not implemented
    Param (
        [Object]$avdgwip
    )

    $a = @()
    $avdgwip | ForEach-Object {
        $a += test-avdgwapi -avdgwip $_.
        $a
    }



}

# Invoke-PathPing performs a pathping to the AVD Gateway IP passed in as $RemoteHost parameter
# Defining -q will allow you to specify the number of pings to perform on each hop of the traceroute. Default = 5 pings
# Larger -q value will take longer to perform but provide more accurate results
function Invoke-PathPing {
    param([string]$avdgwip,
        [int]$q = 100 
    )
    
    PATHPING -q $q -4 -n $avdgwip | ForEach-Object {
        if ($_.Trim() -match "Tracing route to .*") {
            Write-Host $_ -ForegroundColor Yellow
        } 
        elseif ($_.Trim() -match "^\d{1,}\s+\d{1,}ms|^\d{1,}\s+---") {
            # Match the statistics output of pathping for each hop
            # Match the output of the pathping command for the hop number and stats
            Write-Host $_ -ForegroundColor Green
            #$hop, $RTT, $s2hls, $s2hlsperc, $s2lls, $s2llsperc, $hopip = ($_.Trim()).Replace(([regex]::Escape('\/\s{0,3}')), '/').Replace('=', '').Replace('|', '').Replace('---', 0) -split "\s{1,}" | where-object { $_ }
            $hop, $RTT, $s2hls, $s2hlsperc, $s2lls, $s2llsperc, $hopip = ($_.Trim()) -Replace '\/\s{0,3}', '/' -Replace '=', '' -Replace '|', '' -Replace '---', 0 -split "\s{1,}" | where-object { $_ }


            [PSCustomObject]@{
                HopCount     = [int]$hop;
                RTT          = [int]$RTT.Trim('ms');
                S2HLS        = $s2hls;
                S2HLSPercent = [int]$s2hlsperc.Trim('%');
                S2LLS        = $s2lls;
                S2LLSPercent = [int]$s2llsperc.Trim('%');
                HopIP        = [string]$hopip.Trim('[', ']');
                SampleCount  = [int]$q;
                HopName      = (Get-Hostname -ip $hopip)
            } # Add the hop statistics to the array as a custom object
        }
        elseif ($_.Trim() -match "^\d{1,2}\s+") {
            # Display the initial hops of the traceroute and the hop address
            Write-Host $_ -ForegroundColor Green
        }
        elseif ($_.Trim() -match "Computing statistics for .*") {
            Write-Host $_ -ForegroundColor Yellow
        } 
    }
}

function Invoke-TestConnection {
    param (
        [cmdletbinding()]
        [Parameter(Mandatory = $true)]
        [array]$PathPingStats,
        [int]$count = 10
    )
    
    
    Write-Host "Beginning Test-Connection for each hop...Please wait" -ForegroundColor Green
    
    Try {
        Test-Connection -ComputerName ($PathPingStats | Where-object S2LLSPercent -ne 100).HopIP -Count $count | ForEach-Object {
            
            [PSCustomObject]@{
                'Ping'                 = $_.Ping;
                'Source'               = $_.Source;
                'HopIP'                = $_.DisplayAddress;
                'RTT'                  = $_.Latency;
                'Destination'          = (Get-Hostname -ip $_.Destination);
                'Status'               = $_.Status;
                #Work to do on these next 2 values to be more accurate
                'StandardDeviationRTT' = ([Math]::Round(($_.Latency | Measure-Object -StandardDeviation).StandardDeviation, 2)); # Std Deviation of all the latency values and round to 2 decimal places
                'AverageRTT'           = ([Math]::Round(($_.Latency | Measure-Object -Average).Average, 2)) # Average of all the latency values and round to 2 decimal places
            }
        }
        Write-Host "Test-Connection complete" -ForegroundColor Green
    }
    Catch {
        Write-Host "Test-Connection failed" -ForegroundColor Red
        Throw $_.Exception.Message
    }
}

    

function Get-Hostname {
    # Retrieve the first PTR record returned for each hop and return IP if no PTR record is found
    param (
        [string]$ip
    )
    Try {
        (Resolve-DnsName $ip -QuickTimeout -Type PTR -TcpOnly)[0].NameHost # Get the hostname for the IP address return first result
    }
    Catch {
        $ip # Return the IP address if the hostname lookup fails 

    }
    
}

function Get-HTMLReport {
    param (
        [cmdletbinding()]
        [Parameter(Mandatory = $true)]
        [array]$PathPingStats,
        [array]$hoprtt,
        [array]$avdgwip,
        [array]$avdgwapi
    )
    $n = 1

    # Check that the necessary PSWriteHTML module is available and if not then install it
    # To remove Admin permission requirement install into CurrentUser scope only

    Try {
        $HTMLModule = "PSWriteHTML"
        Write-Host "Verify PSWriteHTML Module is loaded" -ForegroundColor Green
        If (-not(Get-Module -name $HTMLModule)) {
            If (Get-Module -ListAvailable | Where-Object { $_.Name -eq $HTMLModule }) {
                Write-Host "PSWriteHTML module found, importing into current user scope" -ForegroundColor Yellow
                Import-Module -Name $HTMLModule
            }
            else {
                Write-Host
                Install-Module -Name PSWriteHTML -Scope CurrentUser -AllowClobber -Force
            } 
        }
    }
    Catch {
        Write-Host "PSWriteHTML module not installed" -ForegroundColor Red
        Throw $_.Exception.Message
    }


    # Create the HTML report
    New-HTML -TitleText "AVD Connection Stats" -Online -FilePath .\avd-connection-stats.html {
        New-HTMLSection -HeaderText 'AVD Gateway Details' {
            New-HTMLList -Type Ordered {
                New-HTMLListItem -Text ('AVD Gateway Region: ' + ((get-avdgwlocation -avdgwregioncode $avdgwapi.AVDRegionCode).RegionName)) -FontWeight Bold
                New-HTMLListItem -Text ('AVD Gateway IP: ' + $avdgwip)
                #New-HTMLListItem -Text ('Average Latency to AVD Gateway: ' + $hoprtt[-1].AverageRTT + ' ms')
                New-HTMLListItem -Text "The region and location information provided is approximate and may not be accurate"
                New-HTMLListItem -Text "AVD Gateway location information is provided by the AVD Gateway API"
                New-HTMLListItem -Text "AVD is a global service and Azure Front Door may connect you through a regional gateway based on the location of your request, it may not be the same region as your Session Host VM"
            }

        }
        
        #Generate report with table and line graph for displaying the results of the traceroute to the AVD Gateway
        #Highlight values that are outside of the acceptable range for latency
        #Values are in milliseconds and currently set low for testing purposes

        New-HTMLSection -HeaderText 'RTT (ms) latency to AVD Gateway' -CanCollapse {
            New-HTMLTable -DataTable ($hoprtt | Select-Object -Property Ping, Source, Destination, @{L = 'RTT (ms)'; E = { $_.RTT } }, HopIP, Status) {
                New-HTMLTableCondition -Name 'RTT (ms)' -ComparisonType number -Operator lt -Value 40 -BackgroundColor LimeGreen -Color White
                New-HTMLTableCondition -Name 'RTT (ms)' -ComparisonType number -Operator ge -Value 40 -BackgroundColor CarrotOrange -Color White
                New-HTMLTableCondition -Name 'RTT (ms)' -ComparisonType number -Operator ge -Value 80 -BackgroundColor TorchRed -Color White 
            }
            New-HTMLPanel {
                New-HTMLChart -Title 'RTT Latency (ms)' -TitleAlignment center {
                    $PingCount = $hoprtt.Ping | select-object -Unique
                    New-ChartAxisX -Name $PingCount -TitleText 'Count'
                    
                    $hoprtt.Where({ $null -ne $_.Destination }) | Group-Object -property HopIP | Foreach-Object {
                        if ($_.Group.Status -eq 'Success') {       
                            New-ChartLine -Name $_.Group[0].Destination -Value $_.Group.RTT -Curve smooth -Cap round
                        }
                        else {
                            [void]
                        }           
                    }
                }
            }
        }
    
        New-HTMLHorizontalLine
        New-HTMLSection -HeaderText 'PathPing Stats to Gateway' -CanCollapse {
            New-HTMLTableStyle -TextAlign center
            New-HTMLTable -DataTable ($PathPingStats | Select-Object -Property HopCount, @{L = 'RTT (ms)'; E = { $_.RTT } }, @{L = 'Source to Here - Lost/Sent'; E = { $_.S2HLS } }, @{L = 'Source to Here - % Lost'; E = { $_.S2HLSPercent } }, @{L = 'This Node/Link'; E = { $_.S2LLS } }, @{L = 'This Node/Link - % Lost'; E = { $_.S2LLSPercent } }, SampleCount, HopIP, HopName) {
                New-HTMLTableCondition -Name 'Source to Here - % Lost' -ComparisonType number -Operator ge -Value 40 -BackgroundColor CarrotOrange -Color White
                New-HTMLTableCondition -Name 'Source to Here - % Lost' -ComparisonType number -Operator ge -Value 60 -BackgroundColor TorchRed -Color White
                New-HTMLTableCondition -Name 'Source to Here - % Lost' -ComparisonType number -Operator eq -Value 100 -BackgroundColor LightGrey 
                New-HTMLTableCondition -Name 'Source to Here - % Lost' -ComparisonType number -Operator ge -Value 40 -BackgroundColor CarrotOrange -Color White
                New-HTMLTableCondition -Name 'Source to Here - % Lost' -ComparisonType number -Operator ge -Value 60 -BackgroundColor TorchRed -Color White
                New-HTMLTableCondition -Name 'Source to Here - % Lost' -ComparisonType number -Operator eq -Value 100 -BackgroundColor LightGrey
            }
        }
       
        #Plot hops of traceroute to AVD Gateway as a graphic

        New-HTMLHorizontalLine
        New-HTMLSection -HeaderText 'Traceroute to AVD Gateway' -CanCollapse {
            New-HTMLDiagram -Height 'calc(100vh - 20px)' -Width 'calc(100vw - 20px)' {
                New-DiagramOptionsLinks -ArrowsToEnabled $true -ArrowsToType arrow -ArrowsToScaleFactor 1 -FontSize 14 -WidthConstraint 100 -length 100 -FontAlign center #-FontBackground White
                New-DiagramOptionsNodes -Margin 10 -Shape box -WidthConstraintMaximum 120 -FontSize 14 -FontMulti $true
                New-DiagramOptionsPhysics -Enabled $true
                New-DiagramOptionsInteraction -Hover $true
                
                New-DiagramOptionsLayout -HierarchicalSortMethod directed -HierarchicalDirection FromLeftToRight -HierarchicalLevelSeparation 550 #120
                New-DiagramNode -ID 'Client' -Label $env:COMPUTERNAME -IconSolid laptop-code -Level 0 
                
                foreach ($PathPingStat in $PathPingStats) {
                    New-DiagramNode -ID $PathPingStat.HopCount -Level 1 -Label $PathPingStat.HopName -To $PathPingStats[$n].HopCount -Title $PathPingStat.HopIP 
                    New-DiagramLink -From 'Client' -To $PathPingStat.HopCount -Label ('RTT: ' + $PathPingStat.RTT + 'ms') -Dashes $true -Color Grey -FontColor Black
                    
                    New-DiagramNode -ID ('EdgeLocation-' + $PathPingStat.HopIP) -Label ("Edge Location - `n" + ((get-azureedgelocation -PathPingStats $PathPingStat.HopName).City)) -Level 2
                    New-DiagramEdge -From $PathPingStat.HopCount -To ('EdgeLocation-' + $PathPingStat.HopIP) -Label ((get-azureedgelocation -PathPingStats $PathPingStat.HopName).Country) -Color Grey -FontColor Black -ArrowsToType circle -Length 20 -Dashes $true
                    $n++
                }     
                New-DiagramNode -ID $PathPingStats[-1].HopCount -Label $PathPingStats[-1].HopName -To 'AVD GW' -Level 1 -Title $PathPingStats[-1].HopIP 
                New-DiagramNode -ID 'AVD GW' -Label ("AVD GW -`n" + ((get-avdgwlocation -avdgwregioncode $avdgwapi.AVDRegionCode).RegionName)) -Image "https://raw.githubusercontent.com/jbyway/avd-scripts/main/get-avdgwconnectionstats/WVD.png" -Level 1 
                
                New-DiagramNode -ID 'AVDGWRegion' -Label ((get-avdgwlocation -avdgwregioncode $avdgwapi.AVDRegionCode).RegionName) -Level 2
                New-DiagramEdge -To 'AVDGWRegion' -From 'AVD GW' -Label 'AVD GW Region' -Color Grey -FontColor Black -ArrowsToType circle -Length 20 -Dashes $true
                       
            }
        }
    } -ShowHTML

}

function get-avdgwlocation {
    param (
        [cmdletbinding()]
        [Parameter(Mandatory = $true)]
        [object]$avdgwregioncode
    )
    # Determine the path in which client takes to the AVD Gateway determine closest Azure Front Door Edge location used and AVD Gateway Region connected to
    
    if (-not(Test-Path -Path .\avdgatewaylocations.json -PathType Leaf)) {
        try {
            Invoke-WebRequest -uri https://raw.githubusercontent.com/jbyway/avd-scripts/main/get-avdgwconnectionstats/avdgatewaylocations.json -OutFile ./avdgatewaylocations.json
        }
        catch {
            Write-Error "Error: Unable to retrieve Azure Gateway Locations" 
            throw $_.Exception.Message
            throw $_.ErrorDetails.Message
        }
    }
    Get-Content .\avdgatewaylocations.json | convertfrom-json  | where { $_.RegionCode -eq $avdgwregioncode }
}

function get-azureedgelocation {
    param (
        [cmdletbinding()]
        [Parameter(Mandatory = $false)]
        [array]$PathPingStats,
        [array]$hoprtt
    )
    # Determine the path in which client takes to the AVD Gateway determine closest Azure Front Door Edge location used and AVD Gateway Region connected to
    #$avdgwapi.Headers.'x-ms-wvd-service-region'
    

    
    if (-not(Test-Path -Path .\azureedgelocations.json -PathType Leaf)) {
        try {
            Invoke-WebRequest -uri https://raw.githubusercontent.com/jbyway/avd-scripts/main/get-avdgwconnectionstats/azureedgelocations.json -OutFile ./azureedgelocations.json
        }
        catch {
            Write-Host "Error: Unable to retrieve Azure Edge Locations"
            throw $_.Exception.Message
        }
    }
    If (($PathPingStats -match "ntwk.msn.net").Count -eq 1) {
        $edgecode = (($PathPingStats -split { $_ -eq "." })[-4]) -replace ('\d{1,3}', "")
        $edgenodelocation = Get-Content .\azureedgelocations.json | Convertfrom-json | where { $_.RegionCode -eq $edgecode }
        return $edgenodelocation
    }
    else {
        [PSCustomObject]@{
            RegionCode = "N/A"
            RegionName = "N/A"
            Country    = "N/A"
            City       = "N/A"
        }
        return $edgenodelocation
        # Not an Azure Edge Node

    }
}

Start-Transcript -Path .\log.txt -Append -IncludeInvocationHeader


$avdgwip = get-avdgwip
$avdgwapi = get-avdgwapi -avdgwip $avdgwip #-avdgwenvironment "wvd" # For now only use the first IP address of any connections found



$PathPingStats = Invoke-PathPing -avdgwip $avdgwip[0] -q 50

$hoprtt = Invoke-TestConnection -PathPingStats $PathPingStats -count 30




Get-HTMLreport -PathPingStats $PathPingStats -hoprtt $hoprtt -avdgwip $avdgwip[0] -avdgwapi $avdgwapi[0]

Stop-Transcript
