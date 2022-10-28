Function Get-VcsaHealth {
    
    <#
    .SYNOPSIS
        The Get-vcsaHealth will retrieve the current backup configuration
    .PARAMETER vcenter
        vCenter Server Hostname or IP Address
    .PARAMETER vc_user
        VC Username
    .PARAMETER vc_pass
        VC Password
    .EXAMPLE
        Get-vcsaHealth -vcenter 'vcsa-lab003.ad.domain.local' -vc_user 'p.account'
    #> 

    param(
        [Parameter(Mandatory = $true)][string]$vcenter,
        [Parameter(Mandatory = $true)][string]$vc_user,
        [Parameter(Mandatory = $true)][secureString]$vc_pass
    )
 
    $ErrorActionPreference = "Ignore"
    
    if (!$vcenter) { $vcenter = Read-Host  "Please enter vCenter name" }
    if (!$vc_user) { $vc_user = Read-Host  "Please enter an administrator username (administrator@vsphere.local)" }
    if (!$vc_pass) { $vc_pass = Read-Host  | ConvertFrom-SecureString -AsPlainText -Force "Please enter the administrator password" }
    $pass =  ($vc_pass | ConvertFrom-SecureString -AsPlainText)

    # VCSA Health Items
    $applMgmt = "applmgmt"
    $database = "database"
    $databaseStorage = "database-storage"
    $load = "load"
    $mem = "mem"
    $softwarePackages = "software-packages"
    $storage = "storage"
    $swap = "swap"
    
    # VCSA Health Item URL & Paths variables
    $healthItems = ($applMgmt, $databaseStorage, $load, $mem, $softwarePackages, $storage, $swap)
 
    $BaseUrl = "https://" + $vcenter + "/"
    $AuthUrl = $BaseUrl + "api/session"
    $healthBaseUrl = $BaseUrl + "api/appliance/health"
    $systemHealthUrl = $healthBaseUrl + "/system"
     
    # Create API Auth Session
    $auth = $vc_user + ':' + $pass
    $Encoded = [System.Text.Encoding]::UTF8.GetBytes($auth)
    $authorizationInfo = [System.Convert]::ToBase64String($Encoded)
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Authorization", "Basic $($authorizationInfo)")
 
    # Get API Session ID
    $apiSessionId = Invoke-WebRequest $AuthUrl -Method 'POST' -Headers $headers -SkipCertificateCheck
    $sessionId = $apiSessionId.Content | ConvertFrom-Json
 
    # Return System Health Status
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("vmware-api-session-id", $sessionId)
 
    $systemHealth = Invoke-WebRequest $systemHealthUrl -Method 'GET' -Headers $headers -SkipCertificateCheck
    $healthStatus = ($systemHealth.Content | ConvertFrom-Json)

    if ($healthStatus -ne "green") {
        Write-host "The overall health status for $vcenter is $healthStatus." -ForegroundColor Yellow

        Write-Host "Checking database..." -Foreground Cyan -NoNewline

        $dbHealth = Invoke-WebRequest "$healthBaseUrl/$database" -Method 'GET' -Headers $headers -SkipCertificateCheck
        $dbHealthResults = ($dbHealth.Content | ConvertFrom-Json).status
        if ($dbHealthResults -ne 'HEALTHY') {
            Write-Host database health status is $dbHealthResults -ForegroundColor Red
            Write-Host The database health check has a ($dbHealthResults.Content | ConvertFrom-Json).messages.severity message -ForegroundColor Red
            Write-Host ($itemHealth.Content | ConvertFrom-Json).messages.message.default_message -ForegroundColor Red
            Write-Host "This database health status is $dbHealthResults. This may need additional troubleshooting, or may be safely be ignored. No additional information is provided from this API." -ForegroundColor Yellow
        }
        else {
            Write-Host database health status is $dbHealthResults -ForegroundColor Green
        }
        Write-host "Checking all other health items..." -Foreground Yellow
        
        foreach ($item in $healthItems) {
            Write-Host "Checking $item..." -ForegroundColor Cyan -NoNewline
            $itemHealth = Invoke-WebRequest "$healthBaseUrl/$item" -Method 'GET' -Headers $headers -SkipCertificateCheck
            $results = ($itemHealth.Content | ConvertFrom-Json)
            Write-host "$item status is $results." -ForegroundColor Green

            $messagesUrl = $healthBaseUrl + "/" + $item + "/messages"
            
            if ($results -ne "green") {
                $healthMessage = Invoke-WebRequest "$messagesUrl" -Method 'GET' -Headers $headers -SkipCertificateCheck
                if ((!$healthMessage.Content) | ConvertTo-Json) {
                    $message = ($healthMessage.Content | ConvertFrom-Json).message.default_message
                    Write-Host "Message: $item $message" -ForegroundColor "Yellow"
                    $resolution = ($healthMessage.Content | ConvertFrom-Json).resolution.default_message
                    Write-Host "Resolution: $item $resolution" -ForegroundColor "Yellow"
                }
                else {
                    Write-Host "The $item has no messages to read. Checking for additional messages." -ForegroundColor Cyan
                    Write-Host The $item health check has a ($itemHealth.Content | ConvertFrom-Json).messages.severity message -ForegroundColor Red
                    Write-Host ($itemHealth.Content | ConvertFrom-Json).messages.message.default_message -ForegroundColor Red
                    Write-Host "This may need additional troubleshooting, or may be safely be ignored. No additional information is provided from this API." -ForegroundColor Yellow
                }
            }
        }
    }
    else { Write-host "VCSA Health Checks Passed!" -ForegroundColor "Green" }
}

Function Get-VcsaVersion {
    
    <#
    .SYNOPSIS
        The Get-vcsaVersion will retrieve the current VCSA version
    .PARAMETER vcenter
        vCenter Server Hostname or IP Address
    .PARAMETER vc_user
        VC Username
    .PARAMETER vc_pass
        VC Password
    .EXAMPLE
        Get-vcsaVersion -vcenter 'vcsa-lab003.domain.local' -vc_user 'administrator@vsphere.local'
    #> 

    param(
        [Parameter(Mandatory = $true)][string]$vcenter,
        [Parameter(Mandatory = $true)][string]$vc_user,
        [Parameter(Mandatory = $true)][secureString]$vc_pass
    )
 
    $ErrorActionPreference = "Ignore"
    
    if (!$vcenter) { $vcenter = Read-Host  "Please enter vCenter name" }
    if (!$vc_user) { $vc_user = Read-Host  "Please enter an administrator username (administrator@vsphere.local)" }
    if (!$vc_pass) { $vc_pass = Read-Host  | ConvertFrom-SecureString -AsPlainText -Force "Please enter the administrator password" }
 
    $BaseUrl = "https://" + $vcenter + "/"
    $AuthUrl = $BaseUrl + "api/session"
    $systemBaseUrl = $BaseUrl + "api/appliance/system"
    $systemVersionUrl = $systemBaseUrl + "/version"
     
    # Create API Auth Session
    $auth = $vc_user + ':' + ($vc_pass | ConvertFrom-SecureString -AsPlainText)
    $Encoded = [System.Text.Encoding]::UTF8.GetBytes($auth)
    $authorizationInfo = [System.Convert]::ToBase64String($Encoded)
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Authorization", "Basic $($authorizationInfo)")
 
    # Get API Session ID
    $apiSessionId = Invoke-WebRequest $AuthUrl -Method 'POST' -Headers $headers -SkipCertificateCheck
    $sessionId = $apiSessionId.Content | ConvertFrom-Json
    if ($null -eq $sessionId) {
        Write-Host "VCSA Version is 6.7.*"
        $AuthUrl = $BaseUrl + "rest/com/vmware/cis/session"
        $headers.Add("vmware-use-header-authn", "Basic $($authorizationInfo)")
        $headers.Add("Content-Type", "application/json")
        $apiSessionId = Invoke-WebRequest $AuthUrl -Method 'POST' -Headers $headers -SkipCertificateCheck
        $sessionId = $apiSessionId.Content | ConvertFrom-Json

        # Return VCSA Information
        $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
        $headers = @{
            'vmware-api-session-id' = $sessionId.value
        }
        $systemBaseUrl = $BaseUrl + "rest/appliance/system"
        $systemVersionUrl = $systemBaseUrl + "/version"

        $headers.Add("Content-Type", "application/json")
        $systemVersion = Invoke-WebRequest $systemVersionUrl -Method 'GET' -Headers $headers -SkipCertificateCheck
        $version = ($systemVersion.Content | ConvertFrom-Json).value | Select-Object Version, Build

        Write-Host -ForegroundColor Green "Version:" $version.version
        Write-Host -ForegroundColor Green "Build:" $version.build
    } else {
        Write-Host "VCSA Version is 7.0.*"
        # Return System Health Status
        $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
        $headers.Add("vmware-api-session-id", $sessionId)
    
        $systemVersion = Invoke-WebRequest $systemVersionUrl -Method 'GET' -Headers $headers -SkipCertificateCheck
        $version = ($systemVersion.Content | ConvertFrom-Json) | Select-Object Version, Build

        Write-Host -ForegroundColor Green "Version:" $version.version
        Write-Host -ForegroundColor Green "Build:" $version.build
    }
}

Function Get-VcsaDiskStorage {
    <#
    .PARAMETER vcenter
        vCenter Server Hostname or IP Address
    .PARAMETER ssouser
        VC Username
    .PARAMETER ssopass
        VC Password
    #> 

    param(
        [Parameter(Mandatory = $true)][string]$vcenter,
        [Parameter(Mandatory = $true)][string]$vc_user,
        [Parameter(Mandatory = $true)][secureString]$vc_pass
    )

    $ErrorActionPreference = "Ignore"
    
    if (!$vcenter) { $vcenter = Read-Host  "Please Enter vCenter for health checks" }
    if (!$vc_user) { $vc_user = Read-Host  "Please enter SSO administrator username (administrator@vsphere.local)" }
    if (!$vc_pass) { $vc_pass = Read-Host  | ConvertFrom-SecureString -AsPlainText -Force "Please Enter SSO Password" }
    
    $BaseUrl = "https://" + $vcenter + "/"
    $AuthUrl = $BaseUrl + "api/session"
    $storageBaseUrl = $BaseUrl + "api/appliance/system/storage"

    # Create API Auth Session
    $auth = $vc_user + ':' + ($vc_pass | ConvertFrom-SecureString -AsPlainText)
    $Encoded = [System.Text.Encoding]::UTF8.GetBytes($auth)
    $authorizationInfo = [System.Convert]::ToBase64String($Encoded)
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Authorization", "Basic $($authorizationInfo)")
 
    # Get API Session ID
    $apiSessionId = Invoke-WebRequest $AuthUrl -Method 'POST' -Headers $headers -SkipCertificateCheck
    $sessionId = $apiSessionId.Content | ConvertFrom-Json

    Function Get-vamiDisks {
        <#
            .SYNOPSIS
                This function retrieves VMDK disk number to partition mapping VAMI interface (5480)
                for a VCSA node which can be an Embedded VCSA, External PSC or External VCSA.
            .DESCRIPTION
                Function to return VMDK disk number to OS partition mapping
        #>
        $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
        $headers.Add("vmware-api-session-id", $sessionId)    

        $storageAPI = Invoke-WebRequest $storageBaseUrl -Method 'GET' -Headers $headers -SkipCertificateCheck
        $storageDisks = ($storageAPI.Content | ConvertFrom-Json) | Select-Object Disk, Partition
        $storageDisks
    }
    
    Function Get-vamiStorageUsed {
        <#
                .SYNOPSIS
                    This function retrieves the individual OS partition storage utilization
                    for a VCSA node which can be an Embedded VCSA, External PSC or External VCSA.
                .DESCRIPTION
                    Function to return individual OS partition storage utilization
            #>

        $monitorBaseUrl = $BaseUrl + "api/appliance/monitoring"

        $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
        $headers.Add("vmware-api-session-id", $sessionId) 

        # List of IDs from Get-vamiStatsList to query
        $monitoringAPI = Invoke-WebRequest $monitorBaseUrl -Method 'GET' -Headers $headers -SkipCertificateCheck
        $queryNames = (($monitoringAPI.Content | ConvertFrom-Json) | Where-Object { ($_.name -like "*storage.used.filesystem*") -or ($_.name -like "*storage.totalsize.filesystem*") } | Select-Object id | Sort-Object -Property id)
        $queryName = $queryNames.id

        # Tuple (Filesystem Name, Used, Total) to store results
        $storageStats = @{
            "archive"      = @{"name" = "/storage/archive"; "used" = 0; "total" = 0 };
            "autodeploy"   = @{"name" = "/storage/autodeploy"; "used" = 0; "total" = 0 };
            "boot"         = @{"name" = "/boot"; "used" = 0; "total" = 0 };
            "core"         = @{"name" = "/storage/core"; "used" = 0; "total" = 0 };
            "db"           = @{"name" = "/storage/db"; "used" = 0; "total" = 0 };
            "dblog"        = @{"name" = "/storage/dblog"; "used" = 0; "total" = 0 };
            "imagebuilder" = @{"name" = "/storage/imagebuilder"; "used" = 0; "total" = 0 };
            "lifecycle"    = @{"name" = "/storage/lifecycle"; "used" = 0; "total" = 0 };
            "log"          = @{"name" = "/storage/log"; "used" = 0; "total" = 0 };
            "netdump"      = @{"name" = "/storage/netdump"; "used" = 0; "total" = 0 };
            "root"         = @{"name" = "/root"; "used" = 0; "total" = 0 };
            "updatemgr"    = @{"name" = "/storage/updatemgr"; "used" = 0; "total" = 0 };
            "seat"         = @{"name" = "/storage/seat"; "used" = 0; "total" = 0 };
            "swap"         = @{"name" = "/swap"; "used" = 0; "total" = 0 };
            "vtsdb"        = @{"name" = "/storage/vtsdb"; "used" = 0; "total" = 0 };
            "vtsdblog"     = @{"name" = "/storage/vtsdblog"; "used" = 0; "total" = 0 }
        }
                
        $queryInterval = "DAY1"
        $queryFunction = "MAX"
        $queryStart_time = ((Get-Date).AddDays(-1)).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss') + ".000Z"
        $queryEnd_time = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss') + ".000Z"
                
        $querySpecs = "&interval=" + $queryInterval + "&function=" + $queryfunction + "&start_time=" + $queryStart_time + "&end_time=" + $queryEnd_time
                
        $queryResults = foreach ($item in $queryName) {
            $queryUrl = $monitorBaseUrl + "/query?names=" + $item + $querySpecs
            Invoke-WebRequest $queryUrl -Method 'GET' -Headers $headers -SkipCertificateCheck | Select-Object * -ExcludeProperty Help
        }
        $results = $queryResults.Content | ConvertFrom-Json
            
        foreach ($result in $results) {
            # Update hash if its used storage results
            $key = ((($Result.name).toString()).split(".")[-1]) -replace "coredump", "core" -replace "vcdb_", "" -replace "core_inventory", "db" -replace "transaction_log", "dblog"
            $value = [Math]::Round([int]($result.data[1]).toString() / 1MB, 2)
            if ($result.name -match "used") {
                $storageStats[$key]["used"] = $value
                # Update hash if its total storage results
            }
            else {
                $storageStats[$key]["total"] = $value
            }
        }
            
        $storageResults = @()
        foreach ($key in $storageStats.keys | Sort-Object -Property name) {
            $statResult = [pscustomobject] @{
                Filesystem = $storageStats[$key].name;
                Used       = $storageStats[$key].used;
                Total      = $storageStats[$key].total
            }
            $storageResults += $statResult
        }
        $storageResults
    }

    $vamiDisks = Get-vamiDisks
    $vamiDiskStorage = Get-vamiStorageUsed

    $hashRes = @{}
    foreach ($vamiDisk in $vamiDisks) {
        $hashRes[$vamiDisk.partition] = $vamiDisk
    }

    $storageResults = $vamiDiskStorage | ForEach-Object {
        $pctUsed = ($_.used / $_.total) * 100
        $other = $hashRes[$_.filesystem.Split('/')[-1]]
        [pscustomobject]@{
            Filesystem = $_.filesystem
            UsedGB     = $_.used
            TotalGB    = $_.total
            UsedPct    = [math]::Round($pctUsed, 2)
            HardDisk   = $other.disk
            Partition  = $other.partition
        }
    }

    $storageResults | Sort-Object -Property Partition | Format-Table Filesystem, UsedPct, UsedGB, TotalGB, HardDisk, Partition
    $thresholdPercentage = 80

    foreach ($result in $storageResults) {
        if ($result.usedpct -gt $thresholdPercentage) {
            Write-Host The $result.Partition partition on Hard Disk $result.harddisk is low on disk space. 
            Please extend Hard Disk $result.harddisk or cleanup old log files. -ForegroundColor Red
            Write-Host SSH to the OS of the VCSA and run "'du -a /storage/log | sort -n -r | head -n 20'" to determine the directories to be cleaned up. -ForegroundColor Red
            Write-Host These are the commands to run to clean up the commonly filled directories. -ForegroundColor Red
            Write-Host For VCSA 6.5+ : -ForegroundColor Cyan
            Write-Host "rm /storage/log/vmware/lookupsvc/tomcat/localhost_access*log" -ForegroundColor Yellow
            Write-Host "rm /storage/log/vmware/sso/tomcat/localhost_access*log" -ForegroundColor Yellow
            Write-Host For VCSA 7.0+ : -ForegroundColor Cyan
            Write-Host "rm /storage/log/vmware/lookupsvc/tomcat/localhost_access*log" -ForegroundColor Yellow
            Write-Host "rm /storage/log/vmware/sso/tomcat/localhost_access*log" -ForegroundColor Yellow
            Write-Host "rm /storage/log/vmware/eam/web/localhost_access*log" -ForegroundColor Yellow
        }
    }

}

Function Get-VcsaStorageLogUsage {
    <#
    .PARAMETER vcenter
        vCenter Server Hostname or IP Address
    .PARAMETER vc_user
        VC Username
    .PARAMETER vc_pass
        VC Password
    #>

    param(
        [Parameter(Mandatory = $true)][string]$vcenter,
        [Parameter(Mandatory = $true)][string]$vc_user,
        [Parameter(Mandatory = $true)][secureString]$vc_pass
    )

    $ErrorActionPreference = "Ignore"
    
    if (!$vcenter) { $vcenter = Read-Host  "Please Enter vCenter for health checks" }
    if (!$vc_user) { $vc_user = Read-Host  "Please enter SSO administrator username (administrator@vsphere.local)" }
    if (!$vc_pass) { $vc_pass = Read-Host  | ConvertFrom-SecureString -AsPlainText -Force "Please Enter SSO Password" }

    # VCSA Health Items
    $storage = "storage"
    
    # VCSA Health Item URL & Paths variables
    $healthItems = $storage

    $BaseUrl = "https://" + $vcenter + "/"
    $AuthUrl = $BaseUrl + "api/session"
    $healthBaseUrl = $BaseUrl + "api/appliance/health"
    $systemHealthUrl = $healthBaseUrl + "/system"
    
    # Create API Auth Session
    $auth = $vc_user + ':' + ($vc_pass | ConvertFrom-SecureString -AsPlainText)
    $Encoded = [System.Text.Encoding]::UTF8.GetBytes($auth)
    $authorizationInfo = [System.Convert]::ToBase64String($Encoded)
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Authorization", "Basic $($authorizationInfo)")
 
    # Get API Session ID
    $apiSessionId = Invoke-WebRequest $AuthUrl -Method 'POST' -Headers $headers -SkipCertificateCheck
    $sessionId = $apiSessionId.Content | ConvertFrom-Json
 
    # Return Database Health Status
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("vmware-api-session-id", $sessionId)
 
    $systemHealth = Invoke-WebRequest $systemHealthUrl -Method 'GET' -Headers $headers -SkipCertificateCheck
    $healthStatus = ($systemHealth.Content | ConvertFrom-Json)
    
    if ($healthStatus -ne "green") {
        Write-host "VCSA health status is $healthStatus" -ForegroundColor "Red"

        Write-Host "Checking /storage/log for sufficient space..." -ForegroundColor Cyan

        foreach ($item in $healthItems) {
            Write-Host "Checking $item..." -ForegroundColor Cyan -NoNewline
            $itemHealth = Invoke-WebRequest "$healthBaseUrl/$item" -Method 'GET' -Headers $headers -SkipCertificateCheck
            $results = ($itemHealth.Content | ConvertFrom-Json)
            Write-host "$item status is $results." -ForegroundColor Green

            $messagesUrl = $healthBaseUrl + "/" + $item + "/messages"

            if ($results -ne "green") {
                $healthMessage = Invoke-WebRequest "$messagesUrl" -Method 'GET' -Headers $headers -SkipCertificateCheck
                if ((!$healthMessage.Content) | ConvertTo-Json) {
                    $message = ($healthMessage.Content | ConvertFrom-Json).message.default_message
                    Write-Host "Message: $item $message" -ForegroundColor "Yellow"
                    $resolution = ($healthMessage.Content | ConvertFrom-Json).resolution.default_message
                    Write-Host "Resolution: $item $resolution" -ForegroundColor "Yellow"
                }
                else {
                    Write-Host "The $item has no messages to read. Checking for additional messages." -ForegroundColor Cyan
                    Write-Host The $item health check has a ($itemHealth.Content | ConvertFrom-Json).messages.severity message -ForegroundColor Red
                    Write-Host ($itemHealth.Content | ConvertFrom-Json).messages.message.default_message -ForegroundColor Red
                    Write-Host "This may need additional troubleshooting, or may be safely be ignored. No additional information is provided from this API." -ForegroundColor Yellow
                }
            }
        }
    }
    else { Write-host "VCSA /storage/log has sufficient free space!" -ForegroundColor "Green" }
}