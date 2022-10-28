Function Get-vcsaMachineSslCert {
    <#
    .SYNOPSIS
        Retrieve the current __MACHINE_CERT certificate of the VCSA.
    .DESCRIPTION
        The Get-vCenterSslCert will return information regarding the existing __MACHINE_CERT
        used for the vCenter UI and VCSA VAMI.
    .PARAMETER $vcenter
        vCenter Server FQDN or IP address.
    .PARAMETER $vc_user
        Your username or SSO administrator (administrator@vsphere.local).
    .PARAMETER $vc_pass
        Administrator password.
    .EXAMPLE
        Get-vcsaMachineSslCert -vcenter 'vcsa-lab003.domain.local' -vc_user 'administrator@vsphere.local'
    #>

    param(
        [Parameter(Mandatory = $true)][string]$vcenter,
        [Parameter(Mandatory = $true)][string]$vc_user,
        [Parameter(Mandatory = $true)][secureString]$vc_pass
    )
 
    $ErrorActionPreference = "SilentlyContinue"
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
 
    if (!$vcenter) { $vcenter = Read-Host  "Please enter vCenter name" }
    if (!$vc_user) { $vc_user = Read-Host  "Please enter an administrator username (administrator@vsphere.local)" }
    if (!$vc_pass) { $vc_pass = Read-Host  | ConvertFrom-SecureString -AsPlainText -Force "Please enter the administrator password" }
 
    $BaseUrl = "https://" + $vcenter + "/"
    $AuthUrl = $BaseUrl + "api/session"
    $BaseTlsUrl = $BaseUrl + "api/vcenter/certificate-management/vcenter/tls" 
 
    # Create API Auth Session
    $auth = $vc_user + ':' + ($vc_pass | ConvertFrom-SecureString -AsPlainText)
    $Encoded = [System.Text.Encoding]::UTF8.GetBytes($auth)
    $authorizationInfo = [System.Convert]::ToBase64String($Encoded)
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Authorization", "Basic $($authorizationInfo)")
 
    # Get API Session ID
    $apiSession = Invoke-WebRequest $AuthUrl -Method 'POST' -Headers $headers -SkipCertificateCheck
    $apiSessionId = $apiSession.content | ConvertFrom-Json

    #Test for VCSA 6.7.* or VCSA 7.0.* API and get API Session ID
    if ($null -eq $sessionId) {
        $AuthUrl = $BaseUrl + "rest/com/vmware/cis/session"
        $headers.Add("vmware-use-header-authn", "Basic $($authorizationInfo)")
        $headers.Add("Content-Type", "application/json")
        $apiSessionId = Invoke-WebRequest $AuthUrl -Method 'POST' -Headers $headers -SkipCertificateCheck
        $sessionId = $apiSessionId.Content | ConvertFrom-Json

        # Return Certificate Information
        $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
        $headers = @{
            'vmware-api-session-id' = $sessionId.value
        }
        $BaseTlsUrl = $BaseUrl + "rest/vcenter/certificate-management/vcenter/tls"

        $certInfo = Invoke-WebRequest $BaseTlsUrl -Method 'GET' -Headers $headers -SkipCertificateCheck

        Write-Host "Valid from: " -ForegroundColor Green -NoNewline
        Write-Host ($certInfo.Content | Convertfrom-json).value.valid_from -ForegroundColor White
        Write-Host "Valid to: " -ForegroundColor Green -NoNewline
        Write-Host ($certInfo.Content | Convertfrom-json).value.valid_to -ForegroundColor White
        Write-Host "Issuer: " -ForegroundColor Green -NoNewline
        Write-Host ($certInfo.Content | Convertfrom-json).value.issuer_dn -ForegroundColor White
        Write-Host "SAN: " -ForegroundColor Green -NoNewline
        Write-Host ($certInfo.Content | Convertfrom-json).value.subject_alternative_name -ForegroundColor White
        Write-Host "Issuer: " -ForegroundColor Green -NoNewline
        Write-Host ($certInfo.Content | Convertfrom-json).value.authority_information_access_uri -ForegroundColor White

        # Close API Session ID
        $apiSessionClose = Invoke-WebRequest $AuthUrl -Method 'DELETE' -Headers $headers -SkipCertificateCheck

        if ($apiSessionClose.StatusCode -ne '200') {
            Write-Host "Unable to terminate API session and release token. Please terminate your session manually by closing this terminal." -ForegroundColor DarkYellow
        }
        else {
            Write-Host "You are now logged out of the VCSA API for " -ForegroundColor DarkGreen -NoNewline
            Write-Host "$vcenter." -ForegroundColor DarkYellow  -NoNewline
            Write-Host " Your access token has been released and is no longer valid." -ForegroundColor DarkGreen
        }
    } else {
        # Return Certificate Info
        $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
        $headers.Add("vmware-api-session-id", $apiSessionId)
    
        $certInfo = Invoke-WebRequest $BaseTlsUrl -Method 'GET' -Headers $headers -SkipCertificateCheck

        Write-Host "Valid from: " -ForegroundColor Green -NoNewline
        Write-Host ($certInfo.content | Convertfrom-json).valid_from -ForegroundColor White
        Write-Host "Valid to: " -ForegroundColor Green -NoNewline
        Write-Host ($certInfo.content | Convertfrom-json).valid_to -ForegroundColor White
        Write-Host "Issuer: " -ForegroundColor Green -NoNewline
        Write-Host ($certInfo.content | Convertfrom-json).issuer_dn -ForegroundColor White
        Write-Host "SAN: " -ForegroundColor Green -NoNewline
        Write-Host ($certInfo.content | Convertfrom-json).subject_alternative_name -ForegroundColor White
        Write-Host "Issuer: " -ForegroundColor Green -NoNewline
        Write-Host ($certInfo.content | Convertfrom-json).authority_information_access_uri -ForegroundColor White

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