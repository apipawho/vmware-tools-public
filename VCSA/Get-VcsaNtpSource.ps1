Function Get-VcsaNtpSource {
    <#
    .SYNOPSIS
        Get NTP Source Servers for VMware VCSA via VCSA API
    .DESCRIPTION
        Get NTP Source Servers for VMware VCSA
    .EXAMPLE
        Get-VcsaNtpSource -vcenter 'vcenter.fqdn.com'
    #>

    param(
        [Parameter(Mandatory = $true)][string]$vcenter,
        [Parameter(Mandatory = $true)][string]$vc_user,
        [Parameter(Mandatory = $true)][secureString]$vc_pass
    )

    # Auth variables
    $ErrorActionPreference = "Ignore"
    if (!$vcenter) { $vcenter = Read-Host  "Please enter vCenter name" }
    if (!$vc_user) { $vc_user = Read-Host  "Please enter an administrator username (administrator@vsphere.local)" }
    if (!$vc_pass) { $vc_pass = Read-Host  | ConvertFrom-SecureString -AsPlainText -Force "Please enter the administrator password" }
    
    # Connect to vCenter Server
    $BaseUrl = "https://" + $vcenter + "/"
    $AuthUrl = $BaseUrl + "api/session"
    $NtpUrl = $BaseUrl + "api/appliance/ntp"

    # Create API Auth Session
    $auth = $vc_user + ':' + ($vc_pass | ConvertFrom-SecureString -AsPlainText)
    $Encoded = [System.Text.Encoding]::UTF8.GetBytes($auth)
    $authorizationInfo = [System.Convert]::ToBase64String($Encoded)
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Authorization", "Basic $($authorizationInfo)")

    # Get API Session ID
    $apiSessionId = Invoke-WebRequest $AuthUrl -Method 'POST' -Headers $headers -SkipCertificateCheck
    $sessionId = $apiSessionId.Content | ConvertFrom-Json

    # Test for VCSA 6.7.* or VCSA 7.0.* API and get API Session ID
    if ($null -eq $sessionId) {
        # Swtich to VCSA API 6.7.*
        Write-Host "VCSA API Version is 6.7..."
        $AuthUrl = $BaseUrl + "rest/com/vmware/cis/session"
        $headers.Add("vmware-use-header-authn", "Basic $($authorizationInfo)")
        $headers.Add("Content-Type", "application/json")
        $apiSessionId = Invoke-WebRequest $AuthUrl -Method 'POST' -Headers $headers -SkipCertificateCheck
        $sessionId = $apiSessionId.Content | ConvertFrom-Json

        # Return NTP Information
        $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
        $headers = @{
            'vmware-api-session-id' = $sessionId.value
        }

        $NtpUrl = $BaseUrl + "rest/appliance/ntp"
        $NtpInfo = Invoke-WebRequest $NtpUrl -Method 'GET' -Headers $headers -SkipCertificateCheck
        ($NtpInfo.Content | ConvertFrom-Json).value

        # Close API Session ID
        $apiSessionClose = Invoke-WebRequest $AuthUrl -Method 'DELETE' -Headers $headers -SkipCertificateCheck

        if ($apiSessionClose.StatusCode -ne 200) {
            Write-Host "Unable to terminate API session and release token. Please terminate your session manually by closing this terminal." -ForegroundColor DarkYellow
        }
        else {
            Write-Host "You are now logged out of the VCSA API for " -ForegroundColor DarkGreen -NoNewline
            Write-Host "$vcenter." -ForegroundColor DarkYellow  -NoNewline
            Write-Host " Your access token has been released and is no longer valid." -ForegroundColor DarkGreen
        }
    }
    else {
        Write-Host "VCSA API Version is 7.0"
        # Return NTP Information
        $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
        $headers.Add("vmware-api-session-id", $sessionId)

        $NtpInfo = Invoke-WebRequest $NtpUrl -Method 'GET' -Headers $headers -SkipCertificateCheck
        $NtpInfo.Content | ConvertFrom-Json

        # Close API Session ID
        $apiSessionClose = Invoke-WebRequest $AuthUrl -Method 'DELETE' -Headers $headers -SkipCertificateCheck

        if ($apiSessionClose.StatusCode -ne '204') {
            Write-Host "Unable to terminate API session and release token. Please terminate your session manually by closing this terminal." -ForegroundColor DarkYellow
        }
        else {
            Write-Host "You are now logged out of the VCSA API for " -ForegroundColor DarkGreen -NoNewline
            Write-Host "$vcenter." -ForegroundColor DarkYellow  -NoNewline
            Write-Host " Your access token has been released and is no longer valid." -ForegroundColor DarkGreen
        }
    }
}