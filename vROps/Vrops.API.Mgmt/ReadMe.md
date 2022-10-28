Vrops.API.Mgmt
==============

The APIs within this Module are useful for retrieving the full list of monitored vCenter endpoints, as well as placing a vCenter resource into maintenance mode when performing work on a specific vCenter. It will also place the vCenter out of maintenance mode when work is completed.

Functions
---------------------------
Vrops.API.Mgmt - {'Get-vRopsvCenterList', 'Set-AdapterMaintOn', 'Set-AdapterMaintOff'}


Get-vRopsvCenterList
---------------------------
The Get-vRopsvCenterList retrieves a list of vCenter resources in vROps.

<p>Parameters:<br>
$vrops_user (user2)<br>
$vrops_pass (user2 password)</p>


Set-AdapterMaintOn
---------------------------
The Set-AdapterMaintOn function places the vCenter resource into Maintenance Mode in vROps.

<p>Parameters:<br>
$vcenter (vCenter FQDN)<br>
$vrops_user (user2)<br>
$vrops_pass (user2 password)</p>

```
Set-AdapterMaintOn -vcenter vcsa-lab01.domain.com
```

Set-AdapterMaintOff
---------------------------
The Set-AdapterMaintOff function takes the vCenter resource out Maintenance Mode in vROps .

<p>Parameters:<br>
$vcenter (vCenter FQDN)<br>
$vrops_user (user2)<br>
$vrops_pass (user2 password)</p>

```
Set-AdapterMaintOff -vcenter vcsa-lab01.domain.com
```