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
        [array]$avdgwip
    )
    
    # Retrieve the current AVD Gateway and region from Header
    $ip = $avdgwip.RemoteAddress
    $avdgwapi = Invoke-WebRequest  -Uri https://$ip/api/health -Headers @{Host = "rdgateway.wvd.microsoft.com" } #Potential to make this support Azure GovCloud by making variable
    
       
    # Get AVD Gateway IP address and location details
    
    $avdgwinfo = ConvertFrom-Json $avdgwapi.Content
    $avdgwapi.Headers.'X-AS-CurrentLoad'
    $avdgwapi.Headers.'x-ms-wvd-service-region'

    Write-Verbose "[AVD Gateway Details]"
    "AVD Gateway IP: " + $avdgwip.Address | Write-Verbose -Verbose
    "AVD Gateway Region: " + $avdgwapi.Headers.'x-ms-wvd-service-region' | write-verbose -verbose
    "AVD Gateway Region URL: " + $avdgwinfo.RegionUrl | write-verbose -verbose
    "AVD Gateway Cluster URL: " + $avdgwinfo.ClusterUrl | write-verbose -verbose
   
    return $avdgwapi
}

# This function is not currently used however may be useful in the future
function Invoke-PSPingtoAVDGW {
    param(
        [cmdletbinding()]
        [Parameter(Mandatory = $true)]
        [string]$avdgwip
    )
    
    # Obtain latency of MSRDC connection to remote AVD gateway for any open session
    Write-Verbose "[Begin PSPing to AVD Gateway IP: $avdgwip]`r`n" -Verbose
    
    if ($VerbosePreference -eq 'SilentlyContinue') {
        $latency = .\psping.exe -q ($avdgwip + ":443")
    }
    else {
        $latency = .\psping.exe ($avdgwip + ":443") | write-verbose -Verbose *>&1
    }
    
    $pspingstats = ($latency[-2] -split ',').trim()
    $pspinglatency = ($latency[-1] -split ',').trim()
    
    # Obtain the Gateway Region for this particular AVD Gateway IP
    $web = Invoke-WebRequest -Uri https://$avdgwip/api/health -Headers @{Host = "rdgateway.wvd.microsoft.com" }
    write-Output "Remote Gateway IP: $avdgwip"
    $gwurl = $web.Content | ConvertFrom-Json | select-object -expandproperty 'RegionUrl'
    Write-Output "Gateway URL: $gwurl"
    
    write-output "PSPing Attempts : $pspingstats"
    write-output "PSPing Latency : $pspinglatency"
    Write-Output ""

    # Trace route to the AVD Gateway up to 20 hops
    Write-Output "Gathering Traceroute information. This will take a minute"
    $tracecmd = (TRACERT.EXE -h 3 -w 1500 $avdgwip.RemoteAddress)

    #Write-Output $tracert
    $regex = ‘\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b’
    $tracertips = $tracert | select-string -Pattern $regex -AllMatches | % { $_.Matches } | % { $_.Value } # Get all IP addresses from traceroute output
    $tracertarray += $tracertips

}

#This function is not currently in use
function get-avdgwlatency {
    param(
        [cmdletbinding()]
        [Parameter(Mandatory = $true)]
        [string]$avdgwip
    )
    
    # Obtain latency of MSRDC connection to remote AVD gateway for any open session

    Write-Verbose "[Begin tcpping to AVD Gateway IP: $avdgwip]`r`n" -Verbose
    Write-Verbose "[Ping Gateway IP: $avdgwip]`r`n" -Verbose
    $latency = (.\tcping.exe -n 6 -j -h -f $avdgwip 443)

    $h = @('TCP RTT'
        'TCP Jitter'
        'HTTP RTT'
        'HTTP Jitter')
    # These are the tcping output columns we are looking for
    $numbers = @(-7
        -3
        -5
        -1)
    $i = 0
    $avdgwrtt = @()
    # Obtain the Min, Max, Avg values for the tcp ping results and feed to array
    foreach ($a in $numbers) {
        $avdgwrtt += $latency[$a] | ConvertFrom-CSV -header 'Minimum', 'Maximum', 'Average' |`
            foreach-object { [PSCustomObject]@{ 'Gateway IP' = $avdgwip
                'Test Result'                                = $h[$i]
                'Minimum (ms)'                               = [decimal]$_.Minimum.Trim('Minimum = ').trimend("ms")
                'Maximum (ms)'                               = [decimal]$_.Maximum.Trim("Maximum = ").trimend("ms")
                'Average (ms)'                               = [decimal]$_.Average.Trim("Average = ").trimend("ms") 
            } }
        $i++
    }

    return $latency, $avdgwrtt
   
}

#This function is not currently in use
function get-hopstoavdmap {
    param(
        [cmdletbinding()]
        [Parameter(Mandatory = $false)]
        [string]$avdgwip
    )
    
    # Gather local IP of client and location details
    $clientIP = Invoke-WebRequest -Uri http://ipinfo.io/json | ConvertFrom-Json | select-object -expandproperty 'ip'
    Write-Output "Client Public IP: $clientIP"
    $clientlocation = Invoke-WebRequest -Uri http://ipinfo.io/json | ConvertFrom-Json | select-object -expandproperty 'loc'
    

    # Create array of unique IPs of client and tracert and write to file
    $userIP = $clientIP.Content | ConvertFrom-Json | select-object -expandproperty 'ip'
    $map = @($avdgwip, $userIP, $tracertarray)
    set-content .\ips.txt $map

    # Use ipinfo to get location details of client and display on map
    .\ipinfo.exe map .\ips.txt
}

# Invoke-PathPing performs a pathping to the AVD Gateway IP passed in as $RemoteHost parameter
# Defining -q will allow you to specify the number of pings to perform on each hop of the traceroute. Default = 5 pings
# Larger -q value will take longer to perform but provide more accurate results
function Invoke-PathPing {
    param([string]$RemoteHost,
        [int]$q = 100 
    )
    
    $PathPingStats = @() # Array to hold the results of the traceroute

    PATHPING -q $q -4 -n $RemoteHost | ForEach-Object {
        if ($_.Trim() -match "Tracing route to .*") {
            Write-Host $_ -ForegroundColor Yellow
        } 
        elseif ($_.Trim() -match "^\d{1,3}\s+\d{1,3}ms|^\d{1,2}\s+---") {
            # Match the output of the pathping command for the hop number and stats
            Write-Host $_ -ForegroundColor Green
            $hop, $RTT, $s2hls, $s2hlsperc, $s2lls, $s2llsperc, $hopip = ($_.Trim()).Replace('/   ', '/').Replace('=', '').Replace('|', '') -split "\s{1,}" | where-object {$_}
            $PathPingStatistics = @{
                Hop          = $hop;
                RTT          = $RTT;
                S2HLS        = $s2hls;
                S2HLSPercent = $s2hlsperc;
                S2LLS        = $s2lls;
                S2LLSPercent = $s2llsperc;
                HopIP        = $hopip.Trim('[',']')
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
    foreach ($i in $PathPingStats.Where({ "100%" -ne $_.S2LLSPercent })) { # Filter out any hops that don't respond to ICMP
        $hoprtt += $i.HopIP | ForEach-Object { Test-Connection -TargetName $i.HopIP -Count $count -ResolveDestination -OutVariable h }
    }  
    return $hoprtt      
}

function get-htmlreport {
    param (
        [cmdletbinding()]
        [Parameter(Mandatory = $true)]
        [array]$PathPingStats,
        [array]$hoprtt,
        [array]$avdgwip,
        [array]$avdgwapi
    )
    
    New-HTML -TitleText "AVD Connection Stats" -Online -FilePath .\avd-connection-stats.html {
        New-HTMLSection -HeaderText 'AVD Gateway Details' {
            
        }
        
        #Generate report with table and line graph for displaying the results of the traceroute to the AVD Gateway
        #Highlight values that are outside of the acceptable range for latency
        #Values are in milliseconds and currently set low for testing purposes

        New-HTMLSection -HeaderText 'RTT latency to AVD Gateway' -CanCollapse {
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
    
        #Plot hops of traceroute to AVD Gateway as a graphic

        New-HTMLHorizontalLine
        New-HTMLSection -HeaderText 'Hops to AVD Gateway' -CanCollapse {
            New-HTMLDiagram {
                New-DiagramNode -Label $hoprtt[9].Address.IPAddressToString -IconSolid cloud -Title $hoprtt[9].Destination
                New-DiagramNode -LABEL $hoprtt[12].Address.IPAddressToString -IconSolid laptop-code -Title $hoprtt[12].Destination
                New-DiagramNode -Label $hoprtt[28].Address.IPAddressToString -IconSolid network-wired -Title $hoprtt[28].Destination
                #New-DiagramNode -label "AVD Gateway" -IconBrands windows -Title "rdgateway.wvd.microsoft.com"
                New-DiagramNode -label "AVD Gateway" -Image "https://www.ciraltos.com/wp-content/uploads/2020/05/WVD.png" -Title "rdgateway.wvd.microsoft.com"
                New-DiagramLink -from $hoprtt[9].Address.IPAddressToString -to $hoprtt[12].Address.IPAddressToString -label $hoprtt[12].Latency -ArrowsToEnabled $true -Length 350
                New-DiagramLink -from $hoprtt[12].Address.IPAddressToString -to $hoprtt[28].Address.IPAddressToString -label $hoprtt[28].Latency -ArrowsToEnabled $true -Length 350
                New-DiagramLink -from $hoprtt[28].Address.IPAddressToString -to "AVD Gateway" -label https -ArrowsToEnabled $true -Length 350 -SmoothType dynamic
            } }
    
    New-HTMLHorizontalLine
    New-HTMLSection -HeaderText 'Hops to AVD Gateway' -CanCollapse {
        New-HTMLDiagram {
            New-DiagramNode -Label $hoprtt[9].Address.IPAddressToString -IconSolid cloud -Title $hoprtt[9].Destination
            New-DiagramNode -LABEL $hoprtt[12].Address.IPAddressToString -IconSolid laptop-code -Title $hoprtt[12].Destination
            New-DiagramNode -Label $hoprtt[28].Address.IPAddressToString -IconSolid network-wired -Title $hoprtt[28].Destination
            #New-DiagramNode -label "AVD Gateway" -IconBrands windows -Title "rdgateway.wvd.microsoft.com"
            New-DiagramNode -label "AVD Gateway" -Image "https://www.ciraltos.com/wp-content/uploads/2020/05/WVD.png" -Title "rdgateway.wvd.microsoft.com"
            New-DiagramLink -from $hoprtt[9].Address.IPAddressToString -to $hoprtt[12].Address.IPAddressToString -label $hoprtt[12].Latency -ArrowsToEnabled $true -Length 350
            New-DiagramLink -from $hoprtt[12].Address.IPAddressToString -to $hoprtt[28].Address.IPAddressToString -label $hoprtt[28].Latency -ArrowsToEnabled $true -Length 350
            New-DiagramLink -from $hoprtt[28].Address.IPAddressToString -to "AVD Gateway" -label https -ArrowsToEnabled $true -Length 350 -SmoothType dynamic
        } }
    } -ShowHTML

}


# HTML Report Module 
# Install-Module -Name PSWriteHTML -AllowClobber -Force

$avdgwip, $msrdcpid = get-msrdcavdgwip
$avdgwapi = get-avdgwapi -avdgwip $avdgwip[0]
#$latency, $avdgwrtt = get-avdgwlatency -avdgwip $avdgwip[0].RemoteAddress
$PathPingStats = Invoke-PathPing -RemoteHost $avdgwip.RemoteAddress -q 30
$hoprtt = Invoke-TestConnection -PathPingStats $PathPingStats

get-htmlreport -PathPingStats $PathPingStats -hoprtt $hoprtt -avdgwip $avdgwip -avdgwapi $avdgwapi

