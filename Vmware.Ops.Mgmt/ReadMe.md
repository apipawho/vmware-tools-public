# Vmware.Ops.Mgmt

### [Usage](#Usage:)
The Functions within this Module are useful for managing a variety of vCenter operations and tasks.

---------
Functions
---------------------------
Vmware.Ops.Mgmt - {'Copy-VcRolesAndPermissions','Get-ContentLibrary','Get-ContentLibraryItems','Get-ContentLibraryItemFiles','Move-VMxVCvMotion','Test-Multipath','Update-EsxiRootPwd','Set-EsxiNtpSource','Get-VcsaNtpSource','Set-VcsaNtpSource'}


---------------------------
Copy-VcRolesAndPermissions
---------------------------
The Copy-VcRolesAndPermissions function will copy the role(s) and permissions from one vCenter to another.

<p>Parameters:<br>
$source_vcenter<br>
$dest_vcenter<br>
$source_creds<br>
$dest_creds</p>

```
Copy-VcRolesAndPermissions -source_vcenter vCenterName -dest_vcenter vCenterName
```

-----------------
Move-VMxVCvMotion
---------------------------
The Move-VMxVCvMotion function will relocate a VM from one vCenter to another that is not in the same SSO domain.

<p>Parameters:<br>
$source_vCenter<br>
$dest_vCenter<br>
$virtualMachine<br>
$destNetwork<br>
$dvsName<br>
$cluster<br>
$datastore</p>

--------------
Test-Multipath
---------------------------
Test multipath ESXi LUN paths for proper and consistent configuration across ESXi hosts.

<p>Parameters:<br>
$vc (vCenter FQDN)<br>
$csvout</p>

```
Test-Multipath -vc vCenterName -csvout c:\tmp\file.csv
```

------------------
Update-EsxiRootPwd
---------------------------
This function updates the ESXi root password on all ESXi hosts in all vCenters collected from vROps or a CSV file unless specified as a parameter for only 1 vCenter.

<p>Parameters:<br>
$vcenter (vCenter FQDN)<br>
$rootPassword</p>

```
Update-EsxiRootPwd -vcenter vcsa-lab000.domain.local
```

-----------------
Set-EsxiNtpSource
---------------------------
Stop NTP service temporarily.
Clear current NTP Source Servers.
Add current NTP Source Servers.
Set NTP Service Policy to "on" (Start and stop with host).
Start NTP Service on ESXi hosts.

<p>Parameters:<br>
$vcenter (vCenter FQDN)<br>
$ntpSource</p>

```
Set-EsxiNtpSource -vCenter 'vcenter.fqdn.com'
Set-EsxiNtpSource -vCenter 'vcenter.fqdn.com' -ntpSource "8.8.8.8"
```

------------------
Get-ContentLibrary
---------------------------
This function lists all available vSphere Content Libaries

<p>Parameters:<br>
LibraryName</p>

```
Get-ContentLibrary
Get-ContentLibrary LibraryName
```

-----------------------
Get-ContentLibraryItems
---------------------------
This function lists all items within a given vSphere Content Library

<p>Parameters:<br>
LibraryName<br>
LibraryItemName</p>

```
Get-ContentLibraryItems -LibraryName Test
Get-ContentLibraryItems -LibraryName Test -LibraryItemName TinyPhotonVM
```

----------------------------
Get-ContentLibraryItemFiles
----------------------------
This function lists all item files within a given vSphere Content Library

<p>Parameters:<br>
LibraryName<br>
LibraryItemName</p>

```
Get-ContentLibraryItems -LibraryName Test
Get-ContentLibraryItems -LibraryName Test -LibraryItemName TinyPhotonVM
```

-----------------
Get-VcsaNtpSource
---------------------------
Get NTP Source Servers for VMware VCSA via VCSA API.

<p>Parameters:<br>
$vcenter (vCenter FQDN)<br>
$vc_user<br>
$vc_pass</p>

```
Get-VcsaNtpSource -vcenter 'vcenter.fqdn.com'
```

-----------------
Set-VcsaNtpSource
---------------------------
Set NTP Source Servers for VMware VCSA.

<p>Parameters:<br>
$vcenter (vCenter FQDN)<br>
$ntpSource
$vc_user<br>
$vc_pass</p>

```
Set-VcsaNtpSource -vcenter 'vcenter.fqdn.com'
Set-VcsaNtpSource -vcenter 'vcenter.fqdn.com' -ntpSource "8.8.8.8"
```

-----------------
Get-EsxiNtpServiceRefresh
---------------------------
Refresh ESXi NTP time synchronization

<p>Parameters:<br>
$vcenter (vCenter FQDN)<br>
$vc_user<br>
$vc_pass</p>

```
Get-EsxiNtpServiceRefresh -vcenter 'vcenter.fqdn.com'
```