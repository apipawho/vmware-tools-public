Function Get-vRopsvCenterList {

    <#
    .SYNOPSIS
        The Get-vRopsvCenterList function retrieves a list of vCenter resources in vROps
    .EXAMPLE
        Get-vRopsvCenterList -vrops_user 'admin_account' -vrops_pass 'tH!$isPl@inT3xt'
    #>

    param(
        [Parameter(Mandatory = $true)][string]$vrops_user,
        [Parameter(Mandatory = $true)][secureString]$vrops_pass
    )

    
    if (!$vrops_user) { $vrops_user = Read-Host  "Please enter your username (Example: domain_user)" }
    if (!$vrops_pass) { $vrops_pass = Read-Host  | ConvertFrom-SecureString -AsPlainText -Force "Please enter your password" }
    $pass =  ($vrops_pass | ConvertFrom-SecureString -AsPlainText)

    $vROPsServer = "vrops.domain.com"
    $BaseUrl = "https://" + $vROPsServer + "/suite-api/api"
    $BaseAuthUrl = $BaseUrl + "/auth/token/acquire"
    $LogoutUrl = $BaseUrl + "/auth/token/release"
    $ResourcesUrl = $BaseUrl + "/adapters?_no_links=true"
    
    ## API Request Body
    
    $body = 
    "{
        ""username"" : ""$vrops_user"",
        ""authSource"" : ""AD"",
        ""password"" : ""$pass""
    }"
    
    
    ## Acquire Auth Token
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Accept", "application/json")
    $headers.Add("Content-Type", "application/json")
    $vropsAccess = Invoke-RestMethod -Method 'POST' -Uri $BaseAuthURL -Body $body -Headers $headers
    $token = $vropsAccess.token
    
    
    ## Get vCenter Resource Identifier
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Accept", "application/json")
    $headers.Add("Authorization", "vRealizeOpsToken $token")
    $response = Invoke-RestMethod  -Method 'GET' -Uri $ResourcesUrl -Headers $headers
    $vCenterList = ($response.adapterInstancesInfoDto.resourcekey.resourceIdentifiers | Select-Object $_.value | Where-Object {($_.identifierType.name -eq "VCURL")}).value
    $vCenterList
    Invoke-WebRequest -Method 'POST' -Uri $LogoutUrl -Headers $headers | Out-Null
}

Function Get-vRopsList {
    <#
    .SYNOPSIS
        The Get-VropsList function retrieves a list of resources in vROps    
        Get-VropsList -creds $creds -query [ucs|vc|nsx|esxi|ucsc]  [if esxi, specify -vcenter vcsaname] [if vm, specify -vm vmname]
    .EXAMPLE
        Get-VropsList -creds $creds -query [ucs|vc|nsx|esxi|ucsc] [if esxi, specify -vcenter vcsanmae] [if vm, specify -vm vmname]
    #>
    param(
        [Parameter(Mandatory = $true)][System.Management.Automation.PSCredential]$creds,
        [Parameter(Mandatory = $true)][ValidateSet('vm','vc','esxi', ErrorMessage = "Value '{0}' is invalid. Try one of: '{1}'")][string]$query,
        [Parameter(Mandatory = $false)]$vm,
        [Parameter(Mandatory = $false)]$vcenter
    )
    #which vcenter if underlying hosts query
    if ($query -eq 'esxi' -and !$vcenter) {
        write-host Please supply the -vcenter flag to specify a vCenter
        $vcenter = read-host "vCenter Name we want to query ESXi nodes from"
    }
    if ($vcenter) {
        $vcenter = $vcenter.Split(".")[0]
    }
            
    $url = "https://vrops.copmany.com"
            
    #authstuff
    $password = $creds.GetNetworkCredential().Password
    $user = $creds.username
    $userjson = 
    "{
                ""username"" : ""$user"",
                ""authSource"" : ""AD"",
                ""password"" : ""$password""
            }"
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Accept", "application/json")
    $headers.Add("Content-Type", "application/json")
    $response = Invoke-RestMethod -method Post $url/suite-api/api/auth/token/acquire -body $userjson -Headers $headers
    $token = $response.token
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Accept", "application/json")
    $headers.Add("Authorization", "vRealizeOpsToken $token")
    #pick results based on $query
    if ($query -eq "esxi") {
            
        $vcsaname = $vcenter
        $respUrl = $url + "/suite-api/api/adapters?_no_links=true"
        $response = Invoke-RestMethod  -Headers $headers -Method GET $respUrl
        #data for vcid value
        $res2 = $response.adapterInstancesInfoDto.resourceKey | select $_.Value | where { $_.name -like "*$vcsaname*" -and $_.adapterKindKey -eq "VMWARE" }
        #vcid value of vcsa
        $vcid = ($res2.resourceIdentifiers | select $_.Value | where { $_.identifierType -like "*VMEntityVCID*" }).value
        #new query to resources api
        $respUrl = $url + "/suite-api/api/resources?resourceKind=hostsystem"
        $response = Invoke-RestMethod  -Headers $headers -Method GET $respUrl
        #filer based on vcid
                ($response.resourcelist.resourcekey | where { $_.resourceIdentifiers.value -eq $vcid } | select Name).Name
    }
    if ($query -eq "vm") {
        $respUrl = $url + "/suite-api/api/resources?resourceKind=virtualmachine"
        $response = Invoke-RestMethod  -Headers $headers -Method GET $respUrl
        #find VCID of VM object
        $vcid = (($response.resourcelist.resourcekey | where{$_.name -eq $vm}).resourceidentifiers | where {$_.identifierType -like "*VCID*"}).Value
        $respUrl = $url + "/suite-api/api/adapters?_no_links=true"
        $response = Invoke-RestMethod  -Headers $headers -Method GET $respUrl
        $vcaname = ($response.adapterInstancesInfoDto.resourcekey | where{$_.resourceIdentifiers.value -eq $vcid}).Name
        write-host $vm is in $vcaname
    }       
    if ($query -eq "vc") {
        $respUrl = $url + "/suite-api/api/adapters?_no_links=true"
        $response = Invoke-RestMethod  -Headers $headers -Method GET $respUrl
        $vclist = ($response.adapterInstancesInfoDto.resourcekey.resourceIdentifiers | Select-Object $_.value | Where-Object { ($_.identifierType.name -eq "VCURL") }).value | Sort-Object -unique
        $vclist
    }    
}
Function Set-AdapterMaintOn {

    <#
    .SYNOPSIS
        The Set-AdapterMaintOn function places the vCenter resource into Maintenance Mode in vROps
    .DESCRIPTION
        Set the vCenter resource into Maintenance Mode in vROps to suspend alerting while performing maintenance.
    .EXAMPLE
        Set-AdapterMaintOn -vcenter vcsa-lab003.domain.local
    #>

    #
    param (
        [Parameter(Mandatory = $true)][string]$vrops_user,
        [Parameter(Mandatory = $true)][secureString]$vrops_pass,
        [parameter(Mandatory = $true)][string]$vcenter #FQDN of vCenter server for Maintenance Schedule
    )

    if (!$vrops_user) { $vrops_user = Read-Host  "Please enter your username (Example: domain_user)" }
    if (!$vrops_pass) { $vrops_pass = Read-Host  | ConvertFrom-SecureString -AsPlainText -Force "Please enter your password" }
    if (!$vcenter) { $vcenter = Read-Host  "Please enter the vCenter FQDN to set the manual maintenance schedule in vROps" }
    $pass =  ($vrops_pass | ConvertFrom-SecureString -AsPlainText)

    $vROPsServer = "vrops.domain.com"
    $BaseUrl = "https://" + $vROPsServer + "/suite-api/api"
    $BaseAuthUrl = $BaseUrl + "/auth/token/acquire"
    $LogoutUrl = $BaseUrl + "/auth/token/release"
    $ResourcesUrl = $BaseUrl+"/adapters?_no_links=true"

    ## API Request Body
    $body = 
    "{
        ""username"" : ""$vrops_user"",
        ""authSource"" : ""AD"",
        ""password"" : ""$pass""
    }"

    ## Acquire Auth Token
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Accept", "application/json")
    $headers.Add("Content-Type", "application/json")
    $vropsAccess = Invoke-RestMethod -Method 'POST' -Uri $BaseAuthURL -Body $body -Headers $headers
    $token = $vropsAccess.token


    ## Get vCenter Resource Identifier
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Accept", "application/json")
    $headers.Add("Authorization", "vRealizeOpsToken $token")
    $response = Invoke-RestMethod  -Method 'GET' -Uri $ResourcesUrl -Headers $headers
    $vcAdpapterId = ($response.adapterInstancesInfoDto | Select-Object $_.id | Where-Object {($_.resourcekey.resourceIdentifiers.value -eq $vcenter)}).id

    $MaintUrl = $BaseUrl + "/resources/" + $vcAdpapterId + "/maintained"

    ## Place resource into maintenance
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Accept", "application/json")
    $headers.Add("Authorization", "vRealizeOpsToken $token")
    $maintResponse = Invoke-WebRequest -Method 'PUT' -Uri $MaintUrl -Headers $headers

    if ($maintResponse.StatusCode -ne "200") {
        Write-Host Status Code is $response.StatusCode
        Write-Host $maintResponse.StatusDescription
        Write-Host -ForegroundColor DarkRed "The $vcenter adapter has not been placed into a Maintenance Schedule."
        Write-Host -ForegroundColor DarkRed "Review the Status Code and Status Description from above to troubleshoot."
    }
    else {
        ## Logout of vROps and release auth token
        $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
        $headers.Add("Accept", "application/json")
        $headers.Add("Authorization", "vRealizeOpsToken $token")
        Invoke-WebRequest -Method 'POST' -Uri $LogoutUrl -Headers $headers | Out-Null
        Write-Host -ForegroundColor Green "vCenter $vcenter is now set to a manual maintenance schedule."
        Write-Host -ForegroundColor Green "You are now being logged out of vROps. Your access token has been released and is no longer valid."
    }

}

Function Set-AdapterMaintOff {

    <#
        .SYNOPSIS
    The Set-AdapterMaintOff function takes the vCenter resource out Maintenance Mode in vROps
        .DESCRIPTION
    Remove the vCenter resource from Maintenance Mode in vROps to resume alerting.
        .EXAMPLE
    Set-AdapterMaintOff -vcenter vcsa-lab003.pdx.local
    #>
        
    #
    param (
        [Parameter(Mandatory = $true)][string]$vrops_user,
        [Parameter(Mandatory = $true)][secureString]$vrops_pass,
        [parameter(Mandatory = $true)][string]$vcenter #FQDN of vCenter server for Maintenance Schedule
    )

    if (!$vrops_user) { $vrops_user = Read-Host  "Please enter your username (Example: domain_user)" }
    if (!$vrops_pass) { $vrops_pass = Read-Host  | ConvertFrom-SecureString -AsPlainText -Force "Please enter your password" }
    if (!$vcenter) { $vcenter = Read-Host  "Please enter the vCenter FQDN to set the manual maintenance schedule in vROps" }
    $pass =  ($vrops_pass | ConvertFrom-SecureString -AsPlainText)
        
    $vROPsServer = "vrops.company.com"
    $BaseUrl = "https://" + $vROPsServer + "/suite-api/api"
    $BaseAuthUrl = $BaseUrl + "/auth/token/acquire"
    $LogoutUrl = $BaseUrl + "/auth/token/release"
    $ResourcesUrl = $BaseUrl+"/adapters?_no_links=true"
        
    ## API Request Body
        
    $body = 
    "{
        ""username"" : ""$vrops_user"",
        ""authSource"" : ""AD"",
        ""password"" : ""$pass""
    }"
        
        
    ## Acquire Auth Token
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Accept", "application/json")
    $headers.Add("Content-Type", "application/json")
    $vropsAccess = Invoke-RestMethod -Method 'POST' -Uri $BaseAuthURL -Body $body -Headers $headers
    $token = $vropsAccess.token
        
        
    ## Get vCenter Resource Identifier
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Accept", "application/json")
    $headers.Add("Authorization", "vRealizeOpsToken $token")
    $response = Invoke-RestMethod  -Method 'GET' -Uri $ResourcesUrl -Headers $headers
    $vcAdpapterId = ($response.adapterInstancesInfoDto | Select-Object $_.id | Where-Object {($_.resourcekey.resourceIdentifiers.value -eq $vcenter)}).id
        
    $MaintUrl = $BaseUrl + "/resources/" + $vcAdpapterId + "/maintained"
        
    ## Take resource out of maintenance
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Accept", "application/json")
    $headers.Add("Authorization", "vRealizeOpsToken $token")
    $maintResponse = Invoke-WebRequest -Method 'DELETE' -Uri $MaintUrl -Headers $headers

    if ($maintResponse.StatusCode -ne "200") {
        Write-Host Status Code is $response.StatusCode
        Write-Host $maintResponse.StatusDescription
        Write-Host -ForegroundColor DarkRed "The $vcenter adapter has not been taken out of the Manual Maintenance Schedule."
        Write-Host -ForegroundColor DarkRed "Review the Status Code and Status Description from above to troubleshoot."
    }
    else {
        ## Logout of vROps and release auth token
        $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
        $headers.Add("Accept", "application/json")
        $headers.Add("Authorization", "vRealizeOpsToken $token")
        Invoke-WebRequest -Method 'POST' -Uri $LogoutUrl -Headers $headers | Out-Null
        Write-Host -ForegroundColor Green "vCenter $vcenter is now out of manual maintenance schedule."
        Write-Host -ForegroundColor Green "You are now being logged out of vROps. Your access token has been released and is no longer valid."
    }
    
}