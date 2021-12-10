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
    
    # Retrieve the current AVD Gateway and region from Header
    
    $avdgwapi = $avdgwip.RemoteAddress | Invoke-WebRequest  -Uri ('https://' + $avdgwip.RemoteAddress + '/api/health') -Headers @{Host = "rdgateway.$avdgwenvironment.microsoft.com" } #avdgwenvironment can be used to define whether service is Azure Public, Gov, or China
    #Invoke-WebRequest -uri https://raw.githubusercontent.com/jbyway/avd-scripts/main/get-avdgwconnectionstats/avdgatewaylocations.json -OutFile ./avdgatewaylocations.json
    #Invoke-WebRequest -uri https://raw.githubusercontent.com/jbyway/avd-scripts/main/get-avdgwconnectionstats/azureedgelocations.json -OutFile ./azureedgelocations.json

    # $avdgwapi.Headers.'X-AS-CurrentLoad'
    #$avdgwapi.Headers.'x-ms-wvd-service-region'

    Write-Verbose "[AVD Gateway Details]"
    #$avdgwinfo = ConvertFrom-Json $avdgwapi.Content
    "AVD Gateway IP: " + $avdgwip.RemoteAddress | Write-Verbose -Verbose
    "AVD Gateway Region: " + $avdgwapi.Headers.'x-ms-wvd-service-region' | write-verbose -verbose
    "AVD Gateway Region URL: " + $avdgwinfo.RegionUrl | write-verbose -verbose
    "AVD Gateway Cluster URL: " + $avdgwinfo.ClusterUrl | write-verbose -verbose

    return $avdgwapi
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

            # Try { $hopname = Resolve-DnsName $hopip -QuickTimeout -Type PTR -TcpOnly } #-ErrorAction SilentlyContinue} # Attempt to resolve each hops PTR record but return the IP if unable
            # catch { $hopname = $hopip }

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
    
    #$hoprtt = @()
    Write-Host "Beginning Test-Connection for each hop..." -ForegroundColor Green
    #foreach ($i in $PathPingStats.Where({ 100 -ne $_.S2LLSPercent })) {
    # Filter out any hops that don't respond to ICMP
        
    #$hoprtt += Test-Connection -ComputerName $i.HopIP -ResolveDestination -Count $count
    #        $TestConnection = (Test-Connection -ComputerName $i.HopIP -Count $count)
    #$PathPingStats | Where-Object S2LLSPercent -ne 100 |` # ForEach-Object { 
    #Write-host $_.HopIP -ForegroundColor Green 
    Test-Connection -ComputerName ($PathPingStats | Where-object S2LLSPercent -ne 100).HopIP -Count $count | ForEach-Object  {
            
        [PSCustomObject]@{
            'Ping'                 = $_.Ping;
            'Source'               = $_.Source;
            'HopIP'                = $_.DisplayAddress;
            'RTT'                  = $_.Latency;
            'Destination'          = (Get-Hostname -ip $_.Destination);
            'Status'               = $_.Status;
            'StandardDeviationRTT' = ([Math]::Round(($_.Latency | Measure-Object -StandardDeviation).StandardDeviation, 2)); # Std Deviation of all the latency values and round to 2 decimal places
            'AverageRTT'           = ([Math]::Round(($_.Latency | Measure-Object -Average).Average, 2)) # Average of all the latency values and round to 2 decimal places
        }
    }
    Write-Host "Test-Connection complete" -ForegroundColor Green
}
    

function Get-Hostname {
    param (
        [string]$ip
    )
    Try {
        (Resolve-DnsName $ip -QuickTimeout -Type PTR -TcpOnly)[0].NameHost
    }
    Catch {
        $ip
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

    New-HTML -TitleText "AVD Connection Stats" -Online -FilePath .\avd-connection-stats.html {
        New-HTMLSection -HeaderText 'AVD Gateway Details' {

        }
        
        #Generate report with table and line graph for displaying the results of the traceroute to the AVD Gateway
        #Highlight values that are outside of the acceptable range for latency
        #Values are in milliseconds and currently set low for testing purposes

        New-HTMLSection -HeaderText 'RTT (ms) latency to AVD Gateway' -CanCollapse {
            New-HTMLTable -DataTable ($hoprtt | Select-Object -Property Ping, Source, Destination, @{L='RTT (ms)'; E={$_.RTT}}, HopIP, Status) {
                New-HTMLTableCondition -Name 'RTT (ms)' -ComparisonType number -Operator lt -Value 40 -BackgroundColor LimeGreen -Color White
                New-HTMLTableCondition -Name 'RTT (ms)' -ComparisonType number -Operator ge -Value 40 -BackgroundColor CarrotOrange -Color White
                New-HTMLTableCondition -Name 'RTT (ms)' -ComparisonType number -Operator ge -Value 60 -BackgroundColor TorchRed -Color White 
                
                #New-HTMLTableHeader -Name 'RTT (ms)' -Title 'RTT (ms)' -
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
            New-HTMLTable -DataTable ($PathPingStats | Select-Object -Property HopCount, @{L='RTT (ms)'; E={$_.RTT}}, @{L='Source to Here - Lost/Sent'; E={$_.S2HLS}}, @{L='Source to Here - % Lost'; E={$_.S2HLSPercent}}, @{L='This Node/Link'; E={$_.S2LLS}}, @{L='This Node/Link - % Lost'; E={$_.S2LLSPercent}}, SampleCount, HopIP, HopName) {
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
                New-DiagramOptionsNodes -Margin 10 -Shape box -WidthConstraintMaximum 120 <# 250 #> -FontSize 14 -FontMulti $true
                New-DiagramOptionsPhysics -Enabled $true
                New-DiagramOptionsInteraction -Hover $true
                
                New-DiagramOptionsLayout -HierarchicalSortMethod directed -HierarchicalDirection FromLeftToRight -HierarchicalLevelSeparation 550 #120
                New-DiagramNode -ID 'Client' -Label $env:COMPUTERNAME -IconSolid laptop-code -Level 0  #-To $PathPingStats[0].Hop  
                
                foreach ($PathPingStat in $PathPingStats) {
                    New-DiagramNode -ID $PathPingStat.HopCount -Level 1 <# $n #> -Label $PathPingStat.HopName -To $PathPingStats[$n].HopCount -Title $PathPingStat.HopIP 
                    New-DiagramLink -From 'Client' -To $PathPingStat.HopCount -Label ('RTT: ' + $PathPingStat.RTT + 'ms') -Dashes $true -Color Grey -FontColor Black
                    $n++
                }     
                New-DiagramNode -ID $PathPingStats[-1].HopCount -Label $PathPingStats[-1].HopName -To 'AVD GW' -Level 1 <# ($n -1) #> 
                New-DiagramNode -ID 'AVD GW' -Label 'AVD GW' -Image "https://www.ciraltos.com/wp-content/uploads/2020/05/WVD.png" -Level 1 <# $n #>
                New-DiagramNode -ID 'AVDGWRegion' -Label ((get-avdgwlocation -avdgwapi $avdgwapi).RegionName) -Level 3
                       
            }
        }
    } -ShowHTML

}

function get-avdgwlocation {
    param (
        [cmdletbinding()]
        [Parameter(Mandatory = $false)]
        [array]$PathPingStats,
        [array]$hoprtt,
        [array]$avdgwip,
        [array]$avdgwapi
    )
    # Determine the path in which client takes to the AVD Gateway determine closest Azure Front Door Edge location used and AVD Gateway Region connected to
    #$avdgwapi.Headers.'x-ms-wvd-service-region'
    Invoke-WebRequest -uri https://raw.githubusercontent.com/jbyway/avd-scripts/main/get-avdgwconnectionstats/azureedgelocations.json -OutFile ./azureedgelocations.json
    #$avdgwregion = Get-Content .\avdgatewaylocations.json | convertfrom-json  | where { $_.RegionCode -eq $avdgwapi.Headers.'x-ms-wvd-service-region' }
    Get-Content .\avdgatewaylocations.json | convertfrom-json  | where { $_.RegionCode -eq $avdgwapi.Headers.'x-ms-wvd-service-region' }
}

# HTML Report Module you need to install the following modules prior to running this script

# Requires Admin
# Install-Module -Name PSWriteHTML -AllowClobber -Force

#Local user permissions only
# Install-Module -Name PSWriteHTML -Scope CurrentUser -AllowClobber -Force

$avdgwip = @()
$avdgwapi = @()

$avdgwip, $msrdcpid = get-msrdcavdgwip
$avdgwapi = get-avdgwapi -avdgwip $avdgwip[0] #-avdgwenvironment "wvd" # For now only use the first IP address of any connections found


#$latency, $avdgwrtt = get-avdgwlatency -avdgwip $avdgwip[0].RemoteAddress
$PathPingStats = Invoke-PathPing -avdgwip $avdgwip[0].RemoteAddress #-q 4

$hoprtt = Invoke-TestConnection -PathPingStats $PathPingStats -count 100
$hoprtt = Invoke-TestConnection -PathPingStats 202.142.143.151 -count 100

#$avdtrafficpath = get-avdtrafficpath -avdgwapi $avdgwapi -PathpingStats $PathPingStats

Get-HTMLreport -PathPingStats $PathPingStats -hoprtt $hoprtt -avdgwip $avdgwip[0] -avdgwapi $avdgwapi




