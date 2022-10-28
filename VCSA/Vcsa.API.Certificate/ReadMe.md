Vcsa.API.Certificate
====================

The APIs within this Module are useful for the VCSA Certificate management, more specifically the __MACHINE_CERT that is used for the vCenter UI and VAMI.

Functions
---------------------------
Vcsa.API.Certificate - {'Get-vCenterSslCert', 'New-vCenterTlsCsr', 'Renew-vcsaSignedCert', 'Set-vcTlsCertificate', 'Set-vcTlsCertVcsaSigned'}


Get-vCenterSslCert
---------------------------
The Get-vCenterSslCert will retrieve the existing __MACHINE_CERT certificate.

<p>Parameters:<br>
$vcenter (vCenter FQDN or IP address)<br>
$vc_user (SSO Administrator or p.Account)<br>
$vc_pass (SSO Administrator or p.Account user password)</p>

```
Get-vCenterSslCert -vcenter 'vcsa-lab00.domain.local' -vc_user 'administrator@vsphere.local'
```

<p>Valid from: 1/25/2022 11:06:34 PM<br>
Valid to: 1/25/2024 11:06:34 PM<br>
Issuer: OU=VMware Engineering, O=vcsa-lab003.ad.domain.local, ST=California, C=US, DC=vsphere, DC=, CN=CA<br>
SAN: {admin@domain.local, vcsa-lab003.domain.local}<br>
Issuer: {URIName: https://vcsa-lab003.domain.local/afd/vecs/ca}</p>


New-vCenterTlsCsr
---------------------------
The New-vCenterTlsCsr will generate a Certificate Signing Request (CSR) for the __MACHINE_CERT certificate.

<p>Parameters:<br>
$vcenter (vCenter FQDN or IP address)<br>
$vc_user (SSO Administrator user)<br>
$vc_pass (SSO Administrator user password)<br>
$common_name - (FQDN of the VCSA)<br>
$country - (two character country identifier)<br>
$email_address - (acmeuser@acme.com)<br>
$locality - (the city name (i.e. Seattle)<br>
$organization - (, Inc.)<br>
$organization Unit - (CIE)<br>
$state_or_province - (State)</p>

```
New-vCenterTlsCsr -vcenter 'vcsa-lab003.domain.local' -vc_user 'administrator@vsphere.local' -common_name 'vcsa-lab003.domain.local' -country 'US' -email_address 'acmeuser@acme.com' -locality 'Seattle' -organization 'Acme, Inc.' -organization_unit 'CIE' -state_or_province 'State'
```

Renew-vcsaSignedCert
---------------------------
The Renew-vcsaSignedCert will renew the existing VCSA-signed __MACHINE_CERT certificate.

<p>Parameters:<br>
$vcenter (vCenter FQDN or IP address)<br>
$vc_user (SSO Administrator or p.Account)<br>
$vc_pass (SSO Administrator or p.Account user password)<br>
$duration (Duration in days to renew the certificate; 730 maximum from this method)</p>

```
Renew-vcsaSignedCert -vcenter 'vcsa-lab003.domain.local' -vc_user 'administrator@vsphere.local' -duration 730
```

Set-vcTlsCertificate
---------------------------
The Set-vcTlsCertificate replace the existing VCSA-signed or  CA-signed __MACHINE_CERT certificate with a  CA-signed certificate.

<p>Parameters:<br>
$vcenter (vCenter FQDN or IP address)<br>
$vc_user (SSO Administrator user)<br>
$vc_pass (SSO Administrator user password)<br>
$certfile (This is the newly created certificate in PEM format. This is asking for the local directory where the file is stored - C:\temp\ssl\cert.cer) <br>
$keyfile (This is the private key from the CSR created in Venafi. This is asking for the local directory where the file is stored - C:\temp\ssl\privey.key)</p>

Set-vcTlsCertificate -vcenter 'vcsa-lab003.domain.local' -vc_user 'administrator@vsphere.local' -certfile 'C:\temp\ssl\cert.cer' -keyfile 'C:\temp\ssl\privkey.key'

Set-vcTlsCertVcsaSigned
---------------------------
The Set-vcTlsCertVcsaSigned replace the existing VCSA-signed or  CA-signed __MACHINE_CERT certificate with a VCSA-signed certificate.

<p>Parameters:<br>
$vcenter (vCenter FQDN or IP address)<br>
$vc_user (SSO Administrator user)<br>
$vc_pass (SSO Administrator user password)<br>
$common_name - (FQDN of the VCSA)<br>
$country - (two character country identifier)<br>
$email_address - (acmeuser@acme.com)<br>
$locality - (the city name (i.e. Seattle)<br>
$organization - (, Inc.)<br>
$organization Unit - (CIE)<br>
$state_or_province - (State)</p>

```
Sew-vCenterTlsCsr -vcenter 'vcsa-lab003.domain.local' -vc_user 'administrator@vsphere.local' -common_name 'vcsa-lab003.domain.local' -country 'US' -email_address 'acmeuser@acme.com' -locality 'Seattle' -organization ', Inc.' -organization_unit 'CIE' -state_or_province 'State'
```
