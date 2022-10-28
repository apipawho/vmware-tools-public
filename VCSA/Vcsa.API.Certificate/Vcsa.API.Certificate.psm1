Function Get-vCenterSslCert {

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
        Get-vCenterSslCert -vcenter 'vcsa-lab003.domain.local' -vc_user 'administrator@vsphere.local'
    #>

    param(
          [Parameter(Mandatory = $true)][string]$vcenter,
          [Parameter(Mandatory = $true)][string]$vc_user,
          [Parameter(Mandatory = $true)][secureString]$vc_pass
       )
 
    $ErrorActionPreference = "Stop"
    $global:DefaultCisServers = $null
 
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
 
    if (!$vcenter) { $vcenter = Read-Host  "Please enter vCenter name" }
    if (!$vc_user) { $vc_user = Read-Host  "Please enter an administrator username (administrator@vsphere.local)" }
    if (!$vc_pass) { $vc_pass = Read-Host  | ConvertFrom-SecureString -AsPlainText -Force "Please enter the administrator password" }
 
    $BaseUrl = "https://" + $vcenter + "/api"
    $AuthUrl = $BaseUrl + "/session"
    $BaseTlsUrl = $BaseUrl + "/vcenter/certificate-management/vcenter/tls" 
 
    # Create API Auth Session
    $auth = $vc_user + ':' + ($vc_pass | ConvertFrom-SecureString -AsPlainText)
    $Encoded = [System.Text.Encoding]::UTF8.GetBytes($auth)
    $authorizationInfo = [System.Convert]::ToBase64String($Encoded)
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Authorization", "Basic $($authorizationInfo)")
 
    # Get API Session ID
    $apiSession = Invoke-WebRequest $AuthUrl -Method 'POST' -Headers $headers -SkipCertificateCheck
    $apiSessionId = $apiSession.content | ConvertFrom-Json
 
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
    
}

 Function New-vCenterTlsCsr {

    <#
    .SYNOPSIS
        Create a Certificate Signing Request using the VCSA.
    .DESCRIPTION
        The New-vCenterTlsCsr will create a Certificate Signing Request (CSR) using the VCSA
        to be submitted to another Certificate Authority (CA) to create a CA-signed certificate.
    .PARAMETER $vcenter
        vCenter Server FQDN or IP address.
    .PARAMETER $vc_user
        Your username or SSO administrator (administrator@vsphere.local).
    .PARAMETER $vc_pass
        Administrator password.
    .PARAMETER $body
        Duration (in days) - 730 is the maximum allowed.
    .EXAMPLE
        New-vCenterTlsCsr -vcenter 'vcsa-lab003.domain.local' -vc_user 'administrator@vsphere.local'
    #>

    param(
            [Parameter(Mandatory = $true)][string]$vcenter,
            [Parameter(Mandatory = $true)][string]$vc_user,
            [Parameter(Mandatory = $true)][secureString]$vc_pass,
            [Parameter(Mandatory = $true)][string]$common_name,
            [Parameter(Mandatory = $true)][string]$country,
            [Parameter(Mandatory = $true)][string]$email_address,
            [Parameter(Mandatory = $true)][string]$locality,
            [Parameter(Mandatory = $true)][string]$organization,
            [Parameter(Mandatory = $true)][string]$organization_unit,
            [Parameter(Mandatory = $true)][string]$state_or_province
        )
    
    $ErrorActionPreference = "Stop"
    $global:DefaultCisServers = $null
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
    if (!$vcenter) { $vcenter = Read-Host  "Please enter vCenter name" }
    if (!$vc_user) { $vc_user = Read-Host  "Please enter an administrator username (administrator@vsphere.local)" }
    if (!$vc_pass) { $vc_pass = Read-Host  | ConvertFrom-SecureString -AsPlainText -Force "Please enter the administrator password" }
    
    $BaseUrl = "https://" + $vcenter + "/api"
    $AuthUrl = $BaseUrl + "/session"
    $BaseTlsUrl = $BaseUrl + "/vcenter/certificate-management/vcenter/tls-csr" 

    # Create API Auth Session
    $auth = $vc_user + ':' + ($vc_pass | ConvertFrom-SecureString -AsPlainText)
    $Encoded = [System.Text.Encoding]::UTF8.GetBytes($auth)
    $authorizationInfo = [System.Convert]::ToBase64String($Encoded)
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Authorization", "Basic $($authorizationInfo)")
    
    # Get API Session ID
    $apiSession = Invoke-WebRequest $AuthUrl -Method 'POST' -Headers $headers -SkipCertificateCheck
    $apiSessionId = $apiSession.content | ConvertFrom-Json

    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("vmware-api-session-id", $apiSessionId)
    $headers.Add("Content-Type", "application/json")

    $body = 
    "{
        ""common_name"" : ""$common_name"",
        ""country"" : ""$country"",
        ""email_address"" : ""$email_address"",
        ""key_size"" : 2048,
        ""locality"" : ""$locality"",
        ""organization"" : ""$organization"",
        ""organization_unit"" : ""$organization_unit"",
        ""state_or_province"" : ""$state_or_province""
    }"

    $response = Invoke-WebRequest -Method 'POST' -Uri $BaseTlsUrl -Headers $headers -Body $body -SkipCertificateCheck
    $vcsaCsr = ($response | ConvertFrom-Json).csr
    $vcsaCsr
    
}

Function Renew-vcsaSignedCert {

    <#
    .SYNOPSIS
        Renew the existing VCSA-signed __MACHINE_CERT certificate.
    .DESCRIPTION
        The Renew-vcsaSignedCert will renew the existing VCSA-signed certificate.
    .PARAMETER vcenter
        vCenter Server FQDN or IP address.
    .PARAMETER vc_user
        Your username or SSO administrator (administrator@vsphere.local).
    .PARAMETER vc_pass
        Administrator password.
    .PARAMETER $body
        Duration (in days) - 730 is the maximum allowed.
    .EXAMPLE
        Renew-vcsaSignedCert -vcenter 'vcsa-lab003.domain.local' -vc_user 'administrator@vsphere.local' -duration 730
    #>

    param(
            [Parameter(Mandatory = $true)][string]$vcenter,
            [Parameter(Mandatory = $true)][string]$vc_user,
            [Parameter(Mandatory = $true)][secureString]$vc_pass,
            [Parameter(Mandatory = $true)][string]$duration
        )
    
    $ErrorActionPreference = "Stop"
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
    if (!$vcenter) { $vcenter = Read-Host  "Please enter vCenter name" }
    if (!$vc_user) { $vc_user = Read-Host  "Please enter an administrator username (administrator@vsphere.local)" }
    if (!$vc_pass) { $vc_pass = Read-Host  | ConvertFrom-SecureString -AsPlainText -Force "Please enter the administrator password" }
    if (!$duration) { $duration = Read-Host  "Please enter renewal duration in numner of days 730 (2 years) maximum" }
    
    $BaseUrl = "https://" + $vcenter + "/api"
    $AuthUrl = $BaseUrl + "/session"
    $BaseTlsUrl = $BaseUrl + "/vcenter/certificate-management/vcenter/tls" 
    $TlsReneweUrl = $BaseTlsUrl + "?action=renew"

    # Create API Auth Session
    $auth = $vc_user + ':' + ($vc_pass | ConvertFrom-SecureString -AsPlainText)
    $Encoded = [System.Text.Encoding]::UTF8.GetBytes($auth)
    $authorizationInfo = [System.Convert]::ToBase64String($Encoded)
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Authorization", "Basic $($authorizationInfo)")
    
    # Get API Session ID
    $apiSession = Invoke-WebRequest $AuthUrl -Method 'POST' -Headers $headers -SkipCertificateCheck
    $apiSessionId = $apiSession.content | ConvertFrom-Json

    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("vmware-api-session-id", $apiSessionId)
    $headers.Add("Content-Type", "application/json")

    $body = 
    "{
        ""duration"" : ""$duration""
    }"

    $response = Invoke-WebRequest -Method 'POST' -Uri $TlsReneweUrl -Headers $headers -Body $body -SkipCertificateCheck
    
    if ($response.BaseResponse.IsSuccessStatusCode -eq "True") {
            Write-Host "VCSA Certificate Renewal was successful!" -ForegroundColor "Green"
            Write-Host "Please allow 5-10 minutes for services to update with the new certificate and restart automatically." -ForegroundColor "Green"
    } else {
            Write-Host "VCSA Certificate Renewal was not successful!" -ForegroundColor "DarkRed"
            Write-Host "Please check that all VCSA services are healthy, and retry the operation."
    }
}

Function Set-vcTlsCertificate {

    <#
    .SYNOPSIS
        Update the VCSA with a CA-signed certificate.
    .DESCRIPTION
        The Set-vcTlsCertVcsaSigned will update the VCSA with a CA-signed certificate.
        The required parameters are set below.
    .PARAMETER $vcenter
        vCenter Server FQDN or IP address
    .PARAMETER $vc_user
        Your username or SSO administrator (administrator@vsphere.local)
    .PARAMETER $vc_pass
        Administrator password
    .PARAMETER $certfile
        The $certfile is the PATH and FILENAME of the certificate in PEM format.
    .PARAMETER $keyfile
        The $keyfile is the PATH and FILENAME of the private key in PEM format.
    .EXAMPLE
        Set-vcTlsCertVcsaSigned -vcenter 'vcsa-lab003.domain.local' -vc_user 'administrator@vsphere.local'
        -common_name 'vcsa-lab003.domain.local' -country 'US' -email_address acmeuser@acme.com'
        -locality 'Seattle' -organization 'Company, Inc.' -organization_unit 'Engineering' -state_or_province 'California'
    #>

    param(
            [Parameter(Mandatory = $true)][string]$vcenter,
            [Parameter(Mandatory = $true)][string]$vc_user,
            [Parameter(Mandatory = $true)][secureString]$vc_pass,
            [Parameter(Mandatory = $true)][string]$certfile,
            [Parameter(Mandatory = $true)][string]$keyfile
            #[Parameter(Mandatory = $true)][string]$rootfile
        )
    
    $ErrorActionPreference = "Stop"
    $global:DefaultCisServers = $null
    if (!$vcenter) { $vcenter = Read-Host  "Please enter vCenter name" }
    if (!$vc_user) { $vc_user = Read-Host  "Please enter an administrator username (administrator@vsphere.local)" }
    if (!$vc_pass) { $vc_pass = Read-Host  | ConvertFrom-SecureString -AsPlainText -Force "Please enter the administrator password" }
    if (!$certfile) { $certfile = Read-Host  "Please provide the PATH of the machine certificate in PEM format (C:\temp\ssl\cert.cer)" }
    if (!$keyfile) { $keyfile = Read-Host  "Please provide the PATH of the machine certificate private key in PEM format (C:\temp\ssl\privkey.key)" }
    #if (!$rootfile) { $rootfile = Read-Host  "Please provide the PATH of the root chain in PEM format (C:\temp\ssl\root.cer)" }
    
    # vCenter Auth and API URLs
    $BaseUrl = "https://" + $vcenter + "/api"
    $AuthUrl = $BaseUrl + "/session"
    $BaseTlsUrl = $BaseUrl + "/vcenter/certificate-management/vcenter/tls"

    # Get PEM file content and convert to base64 string
    $sslcert = (Get-Content $certfile) -replace "`t|`n|`r", ""
    $privatekey = Get-Content $keyfile
    #$root_chain =(Get-Content $rootfile) -replace "`t|`n|`r", ""

    $cert = ((([string]$sslcert).Replace(" ", "")`
        ).Replace("-----BEGINCERTIFICATE-----", "-----BEGIN CERTIFICATE-----\n")`
        ).Replace("-----ENDCERTIFICATE-----", "\n-----END CERTIFICATE-----")

    $key = ((([string]$privatekey).Replace(" ", "")`
        ).Replace("-----BEGINPRIVATEKEY-----", "-----BEGIN PRIVATE KEY-----\n")`
        ).Replace("-----ENDPRIVATEKEY-----", "\n-----END PRIVATE KEY-----")

    #$chain = ((([string]$root_chain).Replace(" ", "")`
    #    ).Replace("-----BEGINCERTIFICATE-----", "-----BEGIN CERTIFICATE-----\n")`
    #    ).Replace("-----ENDCERTIFICATE-----", "\n-----END CERTIFICATE-----")

    # Create API Auth Session
    $auth = $vc_user + ':' + ($vc_pass | ConvertFrom-SecureString -AsPlainText)
    $Encoded = [System.Text.Encoding]::UTF8.GetBytes($auth)
    $authorizationInfo = [System.Convert]::ToBase64String($Encoded)
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Authorization", "Basic $($authorizationInfo)")
    
    # Get API Session ID
    $apiSession = Invoke-WebRequest $AuthUrl -Method 'POST' -Headers $headers -SkipCertificateCheck
    $apiSessionId = $apiSession.content | ConvertFrom-Json

    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("vmware-api-session-id", $apiSessionId)
    $headers.Add("Content-Type", "application/json")

    $body = 
    "{""cert"":""$cert"",
    ""key"":""$key""
    }"

    $response = Invoke-WebRequest -Method 'PUT' -Uri $BaseTlsUrl -Headers $headers -Body $body -SkipCertificateCheck
    $response | ConvertTo-Json
    
        if ($response.BaseResponse.IsSuccessStatusCode -eq "True") {
            Write-Host "VCSA Certificate Replacement was successful!" -ForegroundColor "Green"
            Write-Host "Please allow 5-10 minutes for services to update with the new certificate and restart automatically." -ForegroundColor "Green"
        }
        else {
            Write-Host "VCSA Certificate Replacement was not successful!" -ForegroundColor "DarkRed"
            Write-Host "Please check that all VCSA services are healthy, and retry the operation."
        }

}

Function Set-vcTlsCertVcsaSigned {

    <#
    .SYNOPSIS
        Update the VCSA with a VMCA-signed certificate.
    .DESCRIPTION
        The Set-vcTlsCertVcsaSigned will update the VCSA with a VMCA-signed certificate.
        The required parameters are set below.
    .PARAMETER $vcenter
        vCenter Server FQDN or IP address
    .PARAMETER $vc_user
        Your username or SSO administrator (administrator@vsphere.local)
    .PARAMETER $vc_pass
        Administrator password
    .PARAMETER $body
        Common Name - FQDN of the VCSA
        Country - two character identifier
        Email Address - acmeuser@acme.com
        Locality - The city name (i.e. Seattle)
        Organization - Company, Inc.
        Organization Unit - Engineering
        State or Province - California
    .EXAMPLE
        Set-vcTlsCertVcsaSigned -vcenter 'vcsa-lab003.domain.local' -vc_user 'administrator@vsphere.local'
        -common_name 'vcsa-lab003.domain.local' -country 'US' -email_address 'acmeuser@acme.com'
        -locality 'Seattle' -organization 'Company, Inc.' -organization_unit 'Engineering' -state_or_province 'California'
    #>

    param(
            [Parameter(Mandatory = $true)][string]$vcenter,
            [Parameter(Mandatory = $true)][string]$vc_user,
            [Parameter(Mandatory = $true)][secureString]$vc_pass,
            [Parameter(Mandatory = $true)][string]$common_name,
            [Parameter(Mandatory = $true)][string]$country,
            [Parameter(Mandatory = $true)][string]$email_address,
            [Parameter(Mandatory = $true)][string]$locality,
            [Parameter(Mandatory = $true)][string]$organization,
            [Parameter(Mandatory = $true)][string]$organization_unit,
            [Parameter(Mandatory = $true)][string]$state_or_province
        )
    
    $ErrorActionPreference = "Stop"
    $global:DefaultCisServers = $null
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
    if (!$vcenter) { $vcenter = Read-Host  "Please enter vCenter name" }
    if (!$vc_user) { $vc_user = Read-Host  "Please enter an administrator username (administrator@vsphere.local)" }
    if (!$vc_pass) { $vc_pass = Read-Host  | ConvertFrom-SecureString -AsPlainText -Force "Please enter the administrator password" }
    if (!$common_name) { $common_name = Read-Host  "Please enter the common name (FQDN) for the certificate" }
    if (!$country) { $country = Read-Host  "Please enter the 2-character country code" }
    if (!$email_address) { $email_address = Read-Host  "Please enter an email address" }
    if (!$locality) { $locality = Read-Host  "Please enter a city for locality" }
    if (!$organization) { $organization = Read-Host  "Please enter the organization name (i.e. " }
    if (!$organization_unit) { $organization_unit = Read-Host  "Please enter the Organizational Unit (CIE or Infra_Virt" }
    if (!$state_or_province) { $state_or_province = Read-Host  "Please enter the state or province (i.e. Beaverton)" }
    
    $BaseUrl = "https://" + $vcenter + "/api"
    $AuthUrl = $BaseUrl + "/session"
    $BaseTlsUrl = $BaseUrl + "/vcenter/certificate-management/vcenter/tls" 
    $TlsReplaceUrl = $BaseTlsUrl + "?action=replace-vmca-signed"

    # Create API Auth Session
    $auth = $vc_user + ':' + ($vc_pass | ConvertFrom-SecureString -AsPlainText)
    $Encoded = [System.Text.Encoding]::UTF8.GetBytes($auth)
    $authorizationInfo = [System.Convert]::ToBase64String($Encoded)
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Authorization", "Basic $($authorizationInfo)")
    
    # Get API Session ID
    $apiSession = Invoke-WebRequest $AuthUrl -Method 'POST' -Headers $headers -SkipCertificateCheck
    $apiSessionId = $apiSession.content | ConvertFrom-Json

    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("vmware-api-session-id", $apiSessionId)
    $headers.Add("Content-Type", "application/json")

    $body = 
    "{
        ""common_name"" : ""$common_name"",
        ""country"" : ""$country"",
        ""email_address"" : ""$email_address"",
        ""key_size"" : 2048,
        ""locality"" : ""$locality"",
        ""organization"" : ""$organization"",
        ""organization_unit"" : ""$organization_unit"",
        ""state_or_province"" : ""$state_or_province""
    }"

    $response = Invoke-WebRequest -Method 'POST' -Uri $TlsReplaceUrl -Headers $headers -Body $body -SkipCertificateCheck
    $response | ConvertTo-Json
    
        if ($response.BaseResponse.IsSuccessStatusCode -eq "True") {
            Write-Host "VCSA Certificate Replacement was successful!" -ForegroundColor "Green"
            Write-Host "Please allow 5-10 minutes for services to update with the new certificate and restart automatically." -ForegroundColor "Green"
        }
        else {
            Write-Host "VCSA Certificate Replacement was not successful!" -ForegroundColor "DarkRed"
            Write-Host "Please check that all VCSA services are healthy, and retry the operation."
        }

}

Function Get-vSphereCertDetails {
    <#
        .NOTES
            Created by William Lam, modified by Joel Clyburn
        .DESCRIPTION
            This function returns the certificate mode of vCenter Server along with
            the certificate details of each ESXi hosts being managed by vCenter Server.
            Must be connected to the vCenter via Connect-VIServer
        .EXAMPLE
            Get-vSphereCertDetails
    #>
        if($global:DefaultVIServer.ProductLine -eq "vpx") {
            $vCenterCertMode = (Get-AdvancedSetting -Entity $global:DefaultVIServer -Name vpxd.certmgmt.mode).Value
            Write-Host -ForegroundColor Cyan "`nvCenter $(${global:DefaultVIServer}.Name) Certificate Mode: $vCenterCertMode"
        }
    
        $results = @()
        $vmhosts = Get-View -ViewType HostSystem -Property Name,ConfigManager.CertificateManager
        foreach ($vmhost in $vmhosts) {
            $certConfig = (Get-View $vmhost.ConfigManager.CertificateManager).CertificateInfo
            if($certConfig.Subject -match "vmca@vmware.com") {
                $certType = "VMCA"
            } else {
                $certType = "Custom"
            }
            $tmp = [PSCustomObject] @{
                VMHost = $vmhost.Name;
                CertType = $certType;
                Status = $certConfig.Status;
                Expiry = $certConfig.NotAfter;
            }
            $results+=$tmp
        }
        $results
}