$ErrorActionPreference = 'Stop'

# Determines the current MSRDC processes and returns any active AVD Gateway IPs and the Process ID of the MSRDC Client

function get-msrdcavdgwip {
    [cmdletbinding()]
    Param()

    $avdgwip = @()
    $msrdcpid = @()

    # Get Process ID of MSRDC and IP address of the AVD Gateway in use by any sessions
    Write-Verbose "[Discovering current MSRD Process ID]"
    try {
        $msrdcpid = (Get-Process -Name msrdc).id
        Write-Verbose "[Process ID of MSRDC]"
        $msrdcpid | ForEach-Object { Write-Verbose "$_ `r`n" }

        Write-Verbose "[Discovering currently established AVD Gateway IP(s)]"
        $avdgwip = (Get-NetTCPConnection -OwningProcess $msrdcpid -state Established) | select-object -Unique
    }
    catch {
        "No active connections found for MSRDC"
        Write-Verbose "[No MSRDC processes found]"
    }
    Finally {
        Write-Verbose "[Remote AVD Gateway IP(s) Connected]"
        $avdgwip | Foreach-Object { Write-Verbose "$_ `r" }
    
        Write-Verbose "[Returning AVD GW IP and MSRDC PID]"
        
    }
    
    return $avdgwip, $msrdcpid
}

# Queries the AVD Gateway API health endpoint for the specified AVD Gateway IP and returns the response
function get-avdgwapi {
    [CmdletBinding()]Param(
        [Parameter(Mandatory = $true)]
        [array]$avdgwip,
        [string]$avdgwenvironment = "wvd"
    )
    $avdgwapi = @()
    # Retrieve the current AVD Gateway and region from Header
    $ip = $avdgwip.RemoteAddress
    $avdgwapi = Invoke-WebRequest  -Uri https://$ip/api/health -Headers @{Host = "rdgateway.$avdgwenvironment.microsoft.com" } #avdgwenvironment can be used to define whether service is Azure Public, Gov, or China
    
       
    # Get AVD Gateway IP address and location details
    
    
    # $avdgwapi.Headers.'X-AS-CurrentLoad'
    $avdgwapi.Headers.'x-ms-wvd-service-region'

    Write-Verbose "[AVD Gateway Details]"
    $avdgwinfo = ConvertFrom-Json $avdgwapi.Content
    "AVD Gateway IP: " + $avdgwip.RemoteAddress | Write-Verbose -Verbose
    "AVD Gateway Region: " + $avdgwapi.Headers.'x-ms-wvd-service-region' | write-verbose -verbose
    "AVD Gateway Region URL: " + $avdgwinfo.RegionUrl | write-verbose -verbose
    "AVD Gateway Cluster URL: " + $avdgwinfo.ClusterUrl | write-verbose -verbose
    
    # Obtain the locations of Azure Edge Locations
    $edgelocations = @()
    $azureedgelist = Invoke-WebRequest -uri https://raw.githubusercontent.com/MicrosoftDocs/azure-docs/master/includes/front-door-edge-locations-by-abbreviation.md
    
    $azureedgelist.Content -split "`n" | foreach-object {
        if ($_ -notmatch "^\|\s+[A-Z]{2,3}\s+\|") { [void]::Continue } # Filter out starting lines and only return the lines with the actual data
        else {
            $edgelocations += ($_.TrimStart('|')).TrimEnd('|') -replace ',', '|' | ConvertFrom-Csv -Delimiter '|' -header 'RegionCode', 'City', 'Country', 'AzureRegion', 'Geography' | where RegionCode -match "ZRH"
        }
    }

    # Get the location of the AVD Gateway
    #$avdgwlocation = $edgelocations | where-object { $_.AzureRegion -like $avdgwinfo.Region } | select-object -ExpandProperty Geography
    # $gw = $edgelocations | Select-Object -Property *, @{Name = 'gw'; Expression = {$_.RegionCode -match "PER"}}
    return $avdgwapi, $edgelocations
}

# Invoke-PathPing performs a pathping to the AVD Gateway IP passed in as $RemoteHost parameter
# Defining -q will allow you to specify the number of pings to perform on each hop of the traceroute. Default = 5 pings
# Larger -q value will take longer to perform but provide more accurate results
function Invoke-PathPing {
    param([string]$avdgwip,
        [int]$q = 100 
    )
    
    $PathPingStats = @() # Array to hold the results of the traceroute

    PATHPING -q $q -4 -n $avdgwip | ForEach-Object {
        if ($_.Trim() -match "Tracing route to .*") {
            Write-Host $_ -ForegroundColor Yellow
        } 
        elseif ($_.Trim() -match "^\d{1,}\s+\d{1,}ms|^\d{1,}\s+---") {
            # Match the statistics output of pathping for each hop
            # Match the output of the pathping command for the hop number and stats
            Write-Host $_ -ForegroundColor Green
            $hop, $RTT, $s2hls, $s2hlsperc, $s2lls, $s2llsperc, $hopip = ($_.Trim()).Replace('/   ', '/').Replace('=', '').Replace('|', '').Replace('---', 0) -split "\s{1,}" | where-object { $_ }
            $hopname = Resolve-DnsName $hopip -QuickTimeout -Type PTR -TcpOnly -ErrorAction SilentlyContinue
            $PathPingStatistics = @{
                HopCount     = [int]$hop;
                RTTms        = [int]$RTT.Trim('ms');
                S2HLS        = $s2hls;
                S2HLSPercent = [int]$s2hlsperc.Trim('%');
                S2LLS        = $s2lls;
                S2LLSPercent = [int]$s2llsperc.Trim('%');
                HopIP        = [string]$hopip.Trim('[', ']');
                SampleCount  = [int]$q;
                HopName      = [string]$hopname.NameHost #(Resolve-DnsName $hopip -QuickTimeout -Type PTR -TcpOnly -ErrorAction SilentlyContinue | Select-Object NameHost | Out-String)
            }
            $PathPingStats += New-Object psobject -Property $PathPingStatistics # Add the hop statistics to the array
        }
        elseif ($_.Trim() -match "^\d{1,2}\s+") {
            # Display the initial hops of the traceroute and the hop address
            Write-Host $_ -ForegroundColor Green
        }
        elseif ($_.Trim() -match "Computing statistics for .*") {
            Write-Host $_ -ForegroundColor Yellow
        } 
    }
    
    # Return the sorted array of pathping statistics to the caller
    return $PathPingStats
}

function Invoke-TestConnection {
    param (
        [cmdletbinding()]
        [Parameter(Mandatory = $true)]
        [array]$PathPingStats,
        [int]$count = 10
    )
    
    $hoprtt = @()
    Write-Host "Beginning Test-Connection for each hop..." -ForegroundColor Green
    foreach ($i in $PathPingStats.Where({ "100%" -ne $_.S2LLSPercent })) {
        # Filter out any hops that don't respond to ICMP
        # Need to account for when DNS is not resolved
        $hoprtt += $i.HopIP | ForEach-Object { Test-Connection -ComputerName $i.HopIP -Count $count -ResolveDestination -ErrorAction SilentlyContinue }
    }  
    return $hoprtt      
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

    New-HTML -TitleText "AVD Connection Stats" -Online -FilePath .\avd-connection-stats.html {
        New-HTMLSection -HeaderText 'AVD Gateway Details' {

        }
        
        #Generate report with table and line graph for displaying the results of the traceroute to the AVD Gateway
        #Highlight values that are outside of the acceptable range for latency
        #Values are in milliseconds and currently set low for testing purposes

        New-HTMLSection -HeaderText 'RTT (ms) latency to AVD Gateway' -CanCollapse {
            New-HTMLTable -DataTable ($hoprtt | Select-Object -Property Ping, Source, Destination, Latency, Address, Status) {
                New-HTMLTableCondition -Name 'Latency' -ComparisonType number -Operator lt -Value 40 -BackgroundColor Green -Color White
                New-HTMLTableCondition -Name 'Latency' -ComparisonType number -Operator ge -Value 40 -BackgroundColor CarrotOrange -Color White
                New-HTMLTableCondition -Name 'Latency' -ComparisonType number -Operator ge -Value 60 -BackgroundColor TorchRed -Color White            
            }
            New-HTMLPanel {
                New-HTMLChart -Title 'RTT Latency (ms)' -TitleAlignment center {
                    $hopcount = $hoprtt.Ping | select-object -Unique
                    New-ChartAxisX -Name $hopcount -TitleText 'Count'
                    #$hoprtt | Select-Object Ping, Address, Latency, Status | Foreach-Object {
                    $hoprtt.Where({ $null -ne $_.Address }) | Group-Object -property Address | Foreach-Object {
                        if ($_.Group.Status -eq 'Success') {       
                            New-ChartLine -Name $_.Group[0].Destination -Value $_.Group.Latency -Curve smooth -Cap round
                        }
                        else {
                            Write-Host "Ping timed out"
                        }           
                    }
                }
            }
        }
    
        New-HTMLHorizontalLine
        New-HTMLSection -HeaderText 'PathPing Stats to Gateway' -CanCollapse {
            New-HTMLTable -DataTable ($PathPingStats | Select-Object -Property Hop, RTT, S2HLS, S2HLSPercent, S2LLS, S2LLSPercent, HopIP, SampleCount, HopName) {
                New-HTMLTableCondition -Name 'S2HLS' -ComparisonType number -Operator ge -Value 40 -BackgroundColor CarrotOrange -Color White
                New-HTMLTableCondition -Name 'S2HLS' -ComparisonType number -Operator ge -Value 60 -BackgroundColor TorchRed -Color White
                New-HTMLTableCondition -Name 'S2LLS' -ComparisonType number -Operator ge -Value 40 -BackgroundColor CarrotOrange -Color White
                New-HTMLTableCondition -Name 'S2LLS' -ComparisonType number -Operator ge -Value 60 -BackgroundColor TorchRed -Color White
            }
        }
       
        #Plot hops of traceroute to AVD Gateway as a graphic

        New-HTMLHorizontalLine
        New-HTMLSection -HeaderText 'Traceroute to AVD Gateway' -CanCollapse {
            New-HTMLDiagram -Height 'calc(100vh - 20px)' -Width 'calc(100vw - 20px)' {
                New-DiagramOptionsLinks -ArrowsToEnabled $true -ArrowsToType arrow -ArrowsToScaleFactor 1 -FontSize 14 -WidthConstraint 100 -length 100 -FontAlign center -FontBackground White
                New-DiagramOptionsNodes -Margin 10 -Shape box -WidthConstraintMaximum 120 <# 250 #> -FontSize 14 -FontMulti $true
                New-DiagramOptionsPhysics -Enabled $true
                New-DiagramOptionsInteraction -Hover $true
                
                New-DiagramOptionsLayout -HierarchicalSortMethod directed -HierarchicalDirection FromLeftToRight -HierarchicalLevelSeparation 550 #120
                New-DiagramNode -ID 'Client' -Label $env:COMPUTERNAME -IconSolid laptop-code -Level 0  #-To $PathPingStats[0].Hop  
                
                foreach ($PathPingStat in $PathPingStats) {
                    New-DiagramNode -ID $PathPingStat.Hop -Level 1 <# $n #> -Label $PathPingStat.HopName -To $PathPingStats[$n].Hop -Title $PathPingStat.HopIP 
                    New-DiagramLink -From 'Client' -To $PathPingStat.Hop -Label ('RTT: ' + $PathPingStat.RTT) -Dashes $true -Color Grey -FontBackground white -FontColor Black
                    $n++
                }     
                New-DiagramNode -ID $PathPingStats[-1].Hop -Label $PathPingStats[-1].HopName -To 'AVD GW' -Level 1 <# ($n -1) #> 
                New-DiagramNode -ID 'AVD GW' -Label 'AVD GW' -Image "https://www.ciraltos.com/wp-content/uploads/2020/05/WVD.png" -Level 1 <# $n #>
                       
            }
        }
    } -ShowHTML

}

function get-avdtrafficpath {
    param (
        [cmdletbinding()]
        [Parameter(Mandatory = $false)]
        [array]$PathPingStats,
        [array]$hoprtt,
        [array]$avdgwip,
        [array]$avdgwapi
    )
    # Determine the path in which client takes to the AVD Gateway determine closest Azure Front Door Edge location used and AVD Gateway Region connected to
    $avdgwapi.Headers.'x-ms-wvd-service-region'


    return $avdtrafficpath
}

# HTML Report Module you need to install the following modules prior to running this script

# Requires Admin
# Install-Module -Name PSWriteHTML -AllowClobber -Force

#Local user permissions only
# Install-Module -Name PSWriteHTML -Scope CurrentUser -AllowClobber -Force

$avdgwip = @()
$avdgwapi = @()
$edgelocations = @()
$avdgwip, $msrdcpid = get-msrdcavdgwip
$avdgwapi, $edgelocations = get-avdgwapi -avdgwip $avdgwip[0] #-avdgwenvironment "wvd" # For now only use the first IP address of any connections found


#$latency, $avdgwrtt = get-avdgwlatency -avdgwip $avdgwip[0].RemoteAddress
$PathPingStats = Invoke-PathPing -avdgwip $avdgwip[0].RemoteAddress -q 4
$hoprtt = Invoke-TestConnection -PathPingStats $PathPingStats

#$avdtrafficpath = get-avdtrafficpath -avdgwapi $avdgwapi -PathpingStats $PathPingStats

Get-HTMLreport -PathPingStats $PathPingStats -hoprtt $hoprtt -avdgwip $avdgwip[0] -avdgwapi $avdgwapi




