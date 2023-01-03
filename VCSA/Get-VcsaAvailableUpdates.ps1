Function Get-VcsaAvailableUpdates {
    <#
        .SYNOPSIS
            This function checks for available updates on the VCSA.
        .DESCRIPTION
            vCenter Appliance get available updates function.
        .EXAMPLE
            Get-VcsaAvailableUpdates -vcenter vcsa-lab00.domain.local -ssouser administrator@vsphere.local
    #>

    Param(
        [parameter(Mandatory = $false)][string] $vcenter,
        [parameter(Mandatory = $false)][string] $ssouser,
        [parameter(Mandatory = $false)][secureString] $ssopass
    )

    $ErrorActionPreference = "Stop"
    if (!$vcenter) { $vcenter = Read-Host "Please Enter vCenter to check for available updates" }
    if (!$ssouser) { $ssouser = Read-Host "Please enter SSO administrator username (administrator@vsphere.local)" }
    if (!$ssopass) { $ssopass = Read-Host -assecurestring "Please Enter SSO Password" }
    
    $BaseUrl = "https://" + $vcenter + "/api"
    $AuthUrl = $BaseUrl + "/session"
    $systemBaseUrl = $BaseUrl + "/appliance/system"
    $systemVersionUrl = $systemBaseUrl + "/version"
    $systemUpdateUrl = $BaseUrl + "/appliance/update"
    $systemPendingUrl = $systemUpdateUrl + "/pending"
    $systemCheckUpdateUrl = $systemPendingUrl + "?source_type=LOCAL_AND_ONLINE"

    # Create API Auth Session
    $auth = $ssouser + ':' + ($ssopass | ConvertFrom-SecureString -AsPlainText)
    $Encoded = [System.Text.Encoding]::UTF8.GetBytes($auth)
    $authorizationInfo = [System.Convert]::ToBase64String($Encoded)
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Authorization", "Basic $($authorizationInfo)")
 
    # Get API Session ID
    $apiSessionId = Invoke-WebRequest $AuthUrl -Method 'POST' -Headers $headers -SkipCertificateCheck
    $sessionId = $apiSessionId.Content | ConvertFrom-Json

    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("vmware-api-session-id", $sessionId)

    # Get VCSA Version
    $systemVersion = Invoke-WebRequest $systemVersionUrl -Method 'GET' -Headers $headers -SkipCertificateCheck
    $currentVersion = ($systemVersion.Content | ConvertFrom-Json) | Select-Object Version, Build

    $systemCheckUpdateAPI = Invoke-WebRequest $systemCheckUpdateUrl -Method 'GET' -Headers $headers -SkipCertificateCheck
    $updatesAvailable = ($systemCheckUpdateAPI.Content | ConvertFrom-Json) | Select-Object Name,Version

    # Report VCSA current version and available updates
    Write-Host "$vcenter version is"$currentVersion.version"build"$currentVersion.build"" -ForegroundColor Cyan
    Write-Host "Available updates are below:" -ForegroundColor Yellow
    $updatesAvailable
}