
<#
    .SYNOPSIS
        Returns the latency and quality of connection to the currently connected AVD Gateway.
    .DESCRIPTION
        Identifies the currently connected AVD Gateway and returns the latency and checks for any hops that are potentially causing packet loss.
        Identifies the region of the AVD gateway and your routing path to it. 
    .PARAMETER Count
        The number of pings and packets to send. If not set use default of 20. 
    .PARAMETER ExtendedTest
        If set to true, the extended test is run. This will generate 100 packets and will take an extended amount of time to complete.
    .PARAMETER avdgwenvironment
        The AVD Gateway environment to test. If not set, the default is 'wvd' for the Azure Global environment. Only for use in non-standard environments. 

#>

Param(
    [int]$count = 20,
    [string]$avdgwenvironment = 'wvd',
    [switch]$ExtendedTest = $false
)


# Determines the current MSRDC processes and returns any active AVD Gateway IPs and the Process ID of the MSRDC Client
function get-avdconnectionstats {
    #Not implemented
    [cmdletbinding()]
    Param(
        [bool]$GenerateHTMLReport = $true,
        [switch]$ExtendedTest,
        [int]$count = 20, #default
        [string]$avdgwenvironment = "wvd", # allow for multiple Azure cloud environments
        [System.IO.FileInfo]$Path = ([Environment]::GetFolderPath("Desktop"))
    )

    # Check PowerShell Version is v7 or higher and prompt user to continue if not as some modules may not be available
    if ($PSVersionTable.PSVersion.Major -lt 7) {
        Write-Host 'This script requires PowerShell v7 or higher to run correctly. Please upgrade your PowerShell installation.' 
        while ($(Read-Host "Continue? [Y]es or Ctrl-C to Cancel").ToLower() -ne 'y') {}
    }
    
    if ($ExtendedTest -eq $true) {
        $count = 100 # Run 100 iterations to get a good sample of the data
    }

    [array]$avdgwip = get-avdgwip
    $avdgwapi = get-avdgwapi -avdgwip $avdgwip -avdgwenvironment $avdgwenvironment
    if ($avdgwapi.Count -eq 0) {
        Write-Host 'No AVD Gateway IPs found. Please ensure you are connected to an AVD session and/or have entered the correct AVD Gateway environment.' -ForegroundColor Red
        Write-Host 'If you are connected via RDP Shortpath then you may need to reconnect to your session and try again' -ForegroundColor Red
        Write-Host 'Exiting script!' -ForegroundColor Red
        exit 1
    }
    else {
        $PathPingStats = Invoke-PathPing -avdgwip $avdgwapi[0].RemoteAddress -count $count

        $hoprtt = Invoke-TestConnection -PathPingStats $PathPingStats -count $count
    
        if ($GenerateHTMLReport -eq $true) {
            Get-HTMLreport -PathPingStats $PathPingStats -hoprtt $hoprtt -avdgwip $avdgwapi[0].RemoteAddress -avdgwapi $avdgwapi[0]
        }
    }

}


function get-avdgwip {
    [cmdletbinding()]
    Param()
   
    # Get Process ID of MSRDC and IP address of the AVD Gateway in use by any sessions
    Write-Host "[Discovering current MSRD Process ID]" -ForegroundColor Yellow
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
        Write-Error "[No active AVD Gateway TCP connections found for MSRDC. Please ensure you're connected to an AVD session and not using RDP Shortpath - exiting script!]"
        exit 1
    }
    else {
        $avdgwip = (Get-NetTCPConnection -OwningProcess (Get-Process -Name msrdc).id -state Established -ErrorAction Continue).RemoteAddress | select-Object <#-Property RemoteAddress#> -Unique
        Write-Host "[MSRDC Established TCP Connection(s)]`r" -ForegroundColor Yellow
        $avdgwip | foreach-object { "Remote IP: " + $_ + "`r" | Write-Host -ForegroundColor Green }
    
    }
    
    return [array]$avdgwip

}

# Queries the AVD Gateway API health endpoint for the specified AVD Gateway IP and returns the response
function get-avdgwapi {
    [CmdletBinding()]Param(
        [Parameter(Mandatory = $true)]
        [array]$avdgwip,
        [string]$avdgwenvironment = "wvd"
    )
    
    foreach ($remoteaddress in $avdgwip) { 
        
        #Invoke-WebRequest  -Uri ('https://' + $remoteaddress + '/api/health') -Headers @{Host = "rdgateway.$avdgwenvironment.microsoft.com" } | foreach-object {
        try {
            #Invoke-WebRequest  -Uri ('https://' + $remoteaddress + '/api/health') -Headers @{Host = "rdgateway.$avdgwenvironment.microsoft.com" } 
            
            Invoke-WebRequest  -Uri ('https://' + $remoteaddress + '/api/health') -Headers @{Host = "rdgateway.$avdgwenvironment.microsoft.com" } | foreach-object { 
                [PSCustomObject]@{
                    'RemoteAddress' = $remoteaddress;
                    'AVDRegionCode' = [string]$_.Headers.'x-ms-wvd-service-region';
                    'RegionURL'     = [string](ConvertFrom-Json ($_.Content)).RegionUrl;
                    'Content'       = [object]$_.Content
                }
                Write-Host "`n[AVD Gateway API Response]" -ForegroundColor Yellow
                Write-Host 'AVD Gateway Remote Address:' $remoteaddress -ForegroundColor Green
                Write-Host 'AVD Gateway Region Code:' $_.Headers.'x-ms-wvd-service-region' -ForegroundColor Green
                Write-Host 'AVD Gateway Region:' (get-avdgwlocation -avdgwregioncode $_.Headers.'x-ms-wvd-service-region').RegionName -ForegroundColor Green
                Write-Host 'AVD Gateway Region URL:' (ConvertFrom-Json ($_.Content)).RegionUrl -ForegroundColor Green
            }
            
                
                
        }
        catch {
            Write-Host "`nDetected a connection to" $remoteaddress "but it does not appear to be an AVD Gateway. Skipping it...`n" -ForegroundColor Yellow
        }   
    }

}   

# Invoke-PathPing performs a pathping to the AVD Gateway IP passed in as $RemoteHost parameter
# Defining -q will allow you to specify the number of pings to perform on each hop of the traceroute. Default = 5 pings
# Larger -q value will take longer to perform but provide more accurate results

function Invoke-PathPing {
    param($avdgwip,
        [int]$count = 100 
    )
    Write-Host "`n[PathPing] - Verifying connectivity from your client to the AVD Gateway $avdgwip" -ForegroundColor Yellow
    PATHPING -q $count -4 -n $avdgwip | ForEach-Object {
        if ($_.Trim() -match "Tracing route to .*") {
            Write-Host "[$_]" -ForegroundColor Yellow
        } 
        elseif ($_.Trim() -match "^\d{1,}\s+\d{1,}ms|^\d{1,}\s+---|=\s+\d+%\s+\|") {
            # Match the statistics output of pathping for each hop
            # Match the output of the pathping command for the hop number and stats
          
            
            if ($_.Trim() -match "=\s+\d+%\s+\|") {
                Write-Host $_ -ForegroundColor Green
                $packetloss, $packetlosspercent = ($_.Trim()) -Replace '\/\s{0,3}', '/' -Replace '=', '' -Replace '%', '' -Replace '|', '' -split "\s{1,}" | where-object { $_ }
            }
            else {
                Write-Host $_ -ForegroundColor Green
                $hop, $RTT, $s2hls, $s2hlsperc, $s2lls, $s2llsperc, $hopip = ($_.Trim()) -Replace '\/\s{0,3}', '/' -Replace '=', '' -Replace '|', '' -Replace '---', 0 -split "\s{1,}" | where-object { $_ }
                
                [PSCustomObject]@{
                    HopCount          = [int]$hop;
                    RTT               = [int]$RTT.Trim('ms');
                    S2HLS             = $s2hls;
                    S2HLSPercent      = [int]$s2hlsperc.Trim('%');
                    S2LLS             = $s2lls;
                    S2LLSPercent      = [int]$s2llsperc.Trim('%');
                    HopIP             = [string]$hopip.Trim('[', ']');
                    SampleCount       = [int]$count;
                    HopName           = (Get-Hostname -ip $hopip);
                    PacketLoss        = [string]$packetloss;
                    PacketLossPercent = [int]$packetlosspercent[0]
                }
            }
        }
        elseif ($_.Trim() -match "^\d{1,2}\s+") {
            # Display the initial hops of the traceroute and the hop address
            Write-Host $_ -ForegroundColor Green
        }
        elseif ($_.Trim() -match "Computing statistics for .*") {
            Write-Host "[$_]" -ForegroundColor Yellow
        } 
    }
}

function Invoke-TestConnection {
    param (
        [cmdletbinding()]
        [Parameter(Mandatory = $true)]
        $PathPingStats,
        [int]$count = 20
    )
    
    Write-Host "`n[Test-Connection] - Performing $count ping attempts against each network hop to the AVD Gateway. Please wait..." -ForegroundColor Yellow
    #Write-Host "`rTesting each hop for response time. Performing" $count " attempts ...Please wait" -ForegroundColor Yellow
    
    Try {
        Test-Connection -ComputerName ($PathPingStats | Where-object S2LLSPercent -ne 100).HopIP -Count $count | ForEach-Object {
            if ($_.Ping -eq 1) { $Jitter = 0 } else { $Jitter = ($_.Latency - $latency) } # Determine the jitter between the current latency and the previous latency. First result will be result of first ping
            [PSCustomObject]@{
                'Ping'                 = $_.Ping;
                'Source'               = $_.Source;
                'HopIP'                = $_.DisplayAddress;
                'RTT'                  = $_.Latency;
                'Destination'          = (Get-Hostname -ip $_.Destination);
                'Status'               = $_.Status;
                #Work to do on these next 2 values to be more accurate
                'Jitter'               = $Jitter;
                'StandardDeviationRTT' = ([Math]::Round(($_.Latency | Measure-Object -StandardDeviation).StandardDeviation, 2)); # Std Deviation of all the latency values and round to 2 decimal places
                'AverageRTT'           = ([Math]::Round(($_.Latency | Measure-Object -Average).Average, 2)) # Average of all the latency values and round to 2 decimal places
            }
            Write-Host "Count"$_.Ping ": Hop IP"$_.DisplayAddress": RTT"$_.Latency"ms : Jitter"$Jitter" ms :" $_.Status -ForegroundColor Green 
            $latency = $_.Latency
            
        }
        Write-Host "[Test-Connection complete]`r" -ForegroundColor Yellow
    }
    Catch {
        Write-Host "[Test-Connection failed]" -ForegroundColor Red
        Throw $_.Exception.Message
    }
}

    

function Get-Hostname {
    # Retrieve the first PTR record returned for each hop and return IP if no PTR record is found
    param (
        [string]$ip
    )
    Try {
        $ErrorActionPreference = 'SilentlyContinue'
        (Resolve-DnsName $ip -QuickTimeout -Type PTR -TcpOnly)[0].NameHost # Get the hostname for the IP address return first result
    }
    Catch {
        Write-Host "[No DNS PTR record found for $ip, will use IP instead]" -ForegroundColor Yellow
        $ErrorActionPreference = 'Stop'
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
        Write-Host "`n[Generating HTML report]" -ForegroundColor Yellow
        #Write-Host "`n[Verifying PSWriteHTML module is loaded and install/import if required]" -ForegroundColor Yellow
        If (-not(Get-Module -name $HTMLModule)) {
            If (Get-Module -ListAvailable | Where-Object { $_.Name -eq $HTMLModule }) {
                Write-Host "$HTMLModule module is not loaded, attempting to import]" -ForegroundColor Yellow
                Import-Module -Name $HTMLModule
                Write-Host "$HTMLModule module successfully imported" -ForegroundColor Green
            }
            else {
                Write-Host "Downloading and installing $HTMLModule module - please accept any install prompts" -ForegroundColor Yellow
                Install-Module -Name PSWriteHTML -Scope CurrentUser -AllowClobber -Force
                Write-Host "$HTMLModule module was successfully installed" -ForegroundColor Green
            } 
        }
    }
    Catch {
        Write-Host "The $HTMLModule module failed to load. Please attempt a manual install of the module and rerun the script" -ForegroundColor Red
        Write-Host "'Install-Module -Name $HTMLModule -Scope CurrentUser -AllowClobber -Force'" -ForegroundColor Yellow
        Throw $_.Exception.Message
    }

    
    $date = (Get-Date).ToString("dd-MMM-yyyy-THHmm")
    
    # Create the HTML report
    New-HTML -TitleText "AVD Connection Stats" -Online -FilePath ([Environment]::GetFolderPath("Desktop") + "\AVDConnectionStats-$date.html") {
        New-HTMLSection -HeaderText 'AVD Gateway Details' {
            New-HTMLList -Type Unordered {
                New-HTMLListItem -Text ('AVD Gateway Region: ' + ((get-avdgwlocation -avdgwregioncode $avdgwapi.AVDRegionCode).RegionName)) -FontWeight Bold -FontSize 12
                New-HTMLListItem -Text ('AVD Gateway IP: ' + $avdgwapi.RemoteAddress) -FontSize 12
                New-HTMLListItem -Text "Azure Edge location information may not be accurate and should only be used as a guide."
                New-HTMLListItem -Text "AVD Gateway location information is provided by the AVD Gateway API"
                New-HTMLListItem -Text "AVD is a global service and Azure Front Door may connect you through the closest AVD gateway based on your internet egress location and load balancing algorithms. It may not be the same region as your Session Host VM. Consider this when assessing the overall performance of your connection."
            }

        }
        
        #Generate report with table and line graph for displaying the results of the traceroute to the AVD Gateway
        #Highlight values that are outside of the acceptable range for latency
        #Values are in milliseconds and currently set low for testing purposes

        New-HTMLSection -HeaderText 'RTT (ms) latency to AVD Gateway' -CanCollapse {
            New-HTMLTable -DataTable ($hoprtt | Select-Object -Property Ping, Source, Destination, @{L = 'RTT (ms)'; E = { $_.RTT } }, @{L = 'Jitter (ms)'; E = { $_.Jitter } }, HopIP, Status) {
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
        New-HTMLSection -HeaderText 'PathPing Stats - Description' -CanCollapse -Collapsed {
            New-HTMLList -Type Unordered {
                New-HtmlListItem -Text 'Provides information about network latency and network loss at intermediate hops between a source and destination. This command sends multiple echo Request messages to each router between a source and destination, over a period of time, and then computes results based on the packets returned from each router. Because this command displays the degree of packet loss at any given router or link, you can determine which routers or subnets might be having network problems.'
                New-HTMLListItem -Text "'Source to Here - % Lost' is the percentage of packets that were lost at the router or link between the source and the router or link."
                New-HTMLListItem -Text "'Here to Destination - % Lost' is the percentage of packets that were lost at the router or link between the router or link and the destination."
        }
    }
        New-HTMLSection -HeaderText 'PathPing Stats to Gateway' -CanCollapse {
            New-HTMLTableStyle -TextAlign center
            New-HTMLTable -DataTable ($PathPingStats | Select-Object -Property HopCount, @{L = 'RTT (ms)'; E = { $_.RTT } }, @{L = 'Source to Here - Lost/Sent'; E = { $_.S2HLS } }, @{L = 'Source to Here - % Lost'; E = { $_.S2HLSPercent } }, @{L = 'This Node/Link - Lost/Sent'; E = { $_.S2LLS } }, @{L = 'This Node/Link - % Lost'; E = { $_.S2LLSPercent } }, @{L = 'This Hop Packets Lost/Sent'; E = { $_.packetloss } }, @{L = 'This Hop Packets Lost %'; E = { $_.packetlosspercent } }, SampleCount, HopIP, HopName) {
                New-HTMLTableCondition -Name 'Source to Here - % Lost' -ComparisonType number -Operator ge -Value 40 -BackgroundColor CarrotOrange -Color White
                New-HTMLTableCondition -Name 'Source to Here - % Lost' -ComparisonType number -Operator ge -Value 60 -BackgroundColor TorchRed -Color White
                New-HTMLTableCondition -Name 'Source to Here - % Lost' -ComparisonType number -Operator eq -Value 100 -BackgroundColor LightGrey 
                New-HTMLTableCondition -Name 'Source to Here - % Lost' -ComparisonType number -Operator ge -Value 40 -BackgroundColor CarrotOrange -Color White
                New-HTMLTableCondition -Name 'Source to Here - % Lost' -ComparisonType number -Operator ge -Value 60 -BackgroundColor TorchRed -Color White
                New-HTMLTableCondition -Name 'Source to Here - % Lost' -ComparisonType number -Operator eq -Value 100 -BackgroundColor LightGrey
                New-HTMLTableCondition -Name 'This Hop Packets Lost %' -ComparisonType number -Operator ge -Value 2 -BackgroundColor TorchRed -Color White
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
    Write-Host "Saving to"([Environment]::GetFolderPath("Desktop") + "\AVDConnectionStats-$date.html") -ForegroundColor Yellow

}

function get-avdgwlocation {
    param (
        [cmdletbinding()]
        [Parameter(Mandatory = $true)]
        [object]$avdgwregioncode
    )
    # Determine the path in which client takes to the AVD Gateway determine closest Azure Front Door Edge location used and AVD Gateway Region connected to
    <# Following section is removed for now as replacing with direct query to json on Github. 
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
    #>
    try {
        # Following line not needed when using direct query to json on Github
        #Get-Content .\avdgatewaylocations.json | convertfrom-json  | Where-Object { $_.RegionCode -eq $avdgwregioncode }
        (Invoke-WebRequest -uri https://raw.githubusercontent.com/jbyway/avd-scripts/main/get-avdgwconnectionstats/avdgatewaylocations.json).Content | convertfrom-json | Where-Object { $_.RegionCode -eq $avdgwregioncode }
    }
    catch {
        Write-Error "Error: Unable to retrieve Azure Gateway Locations" 
        throw $_.Exception.Message
        throw $_.ErrorDetails.Message
    }

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
    

    <#
   # Removed the following code as it was easier to query the json directly from the Github file 
    if (-not(Test-Path -Path .\azureedgelocations.json -PathType Leaf)) {
        try {
            Invoke-WebRequest -uri https://raw.githubusercontent.com/jbyway/avd-scripts/main/get-avdgwconnectionstats/azureedgelocations.json -OutFile ./azureedgelocations.json
        }
        catch {
            Write-Host "Error: Unable to retrieve Azure Edge Locations"
            throw $_.Exception.Message
        }
    }
    #>

    # If hop is an Azure Edge location then return the location details
    If (($PathPingStats -match "ntwk.msn.net").Count -eq 1) {
        $edgecode = (($PathPingStats -split { $_ -eq "." })[-4]) -replace ('\d{1,3}', "")
        try {
            $edgenodelocation = (Invoke-WebRequest -uri https://raw.githubusercontent.com/jbyway/avd-scripts/main/get-avdgwconnectionstats/azureedgelocations.json).Content | Convertfrom-json | Where-Object { $_.RegionCode -eq $edgecode }
        }
        catch {
            Write-Host "Error: Unable to retrieve Azure Edge Locations"
            throw $_.Exception.Message
        }
        # Following line is to get the edge location name if using code above to download the json file
        # $edgenodelocation = Get-Content .\azureedgelocations.json | Convertfrom-json | where { $_.RegionCode -eq $edgecode }
       
        return $edgenodelocation
    }
    else {
        # Not an Azure Edge Node so return N/A
        [PSCustomObject]@{
            RegionCode = "N/A"
            RegionName = "N/A"
            Country    = "N/A"
            City       = "N/A"
        }
        return $edgenodelocation
        

    }
}

if ($ExtendedTest -eq $true) {
    $count = 100 # Run 100 iterations. This will run for far longer time so should be done when wanting to perform extended test.
}


get-avdconnectionstats -count $count -avdgwenvironment $avdgwenvironment
