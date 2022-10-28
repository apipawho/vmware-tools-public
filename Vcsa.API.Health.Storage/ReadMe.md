Vcsa.API.Health.Storage
=======================

The APIs within this Module are useful for the overall health of the VCSA, to check the storage usage and cleanup log files taking up additional space on the VCSA.

Functions
---------------------------
Vcsa.API.Health.Storage - {'Get-vcsaHealth', 'Get-vcsaVersion', 'Get-VcsaDiskStorage', 'Get-VcsaStorageLogUsage'}


Get-vcsaHealth
---------------------------
The Get-vcsaHealth will retrieve the health status of the VCSA. If healthy, it will return a message stating as such. If not, a message will display what is unhealthy and what to check.

<p>Parameters:<br>
$vcenter (vCenter FQDN or IP address)<br>
$ssouser (SSO Administrator or p.Account)<br>
$ssopass (SSO Administrator or p.Account user password)</p>

```
Get-vcsaHealth -vcenter 'vcsa-lab00.domain.local' -ssouser 'administrator@vsphere.local'
```

Get-vcsaVersion
---------------------------
The Get-vcsaVersion will retrieve the health status of the VCSA. If healthy, it will return a message stating as such. If not, a message will display what is unhealthy and what to check.

<p>Parameters:<br>
$vcenter (vCenter FQDN or IP address)<br>
$ssouser (SSO Administrator or p.Account)<br>
$ssopass (SSO Administrator or p.Account user password)</p>

```
Get-vcsaVersion -vcenter 'vcsa-lab00.domain.local' -ssouser 'administrator@vsphere.local'
```

Get-VcsaDiskStorage
---------------------------
The Get-VcsaDiskStorage will display the partitions along with their respecitve harddisk and filesystem and usage.

<p>Parameters:<br>
$vcenter (vCenter FQDN or IP address)<br>
$ssouser (SSO Administrator or p.Account)<br>
$ssopass (SSO Administrator or p.Account user password)</p>

```
Get-VcsaDiskStorage -vcenter 'vcsa-lab00.domain.local' -ssouser 'administrator@vsphere.local'
```

EXAMPLE OUTPUT:
|Filesystem         |  UsedPct|UsedGB|TotalGB|HardDisk|Partition|
|----------         |  -------|------|-------|--------|---------|
|/boot              |     8.33|  0.04|   0.48|        |         |
|/storage/archive   |     0.27|  0.26|  97.92| 13|     archive  |
|/storage/autodeploy|     0.16|  0.04|  24.47| 10|      autodeploy|
|/storage/core      |      0.1|  0.05|  48.96| 4 |      core      |
|/storage/db        |     0.69|  0.17|  24.47| 6 |      db        |
|/storage/dblog     |     0.37|  0.09|  24.47| 7 |      dblog     |  
|/storage/imagebuilder|   0.16|  0.04|  24.47| 11|      imagebuilder|
|/storage/lifecycle |     3.12|  3.06|  97.92| 16|      lifecycle |  
|/storage/log       |     4.54|  1.11|  24.47| 5 |      log       |
|/storage/netdump   |     0.41|  0.04|   9.77| 9 |      netdump   |
|/root              |    11.11|  5.22|  46.99| 1 |      root      |  
|/storage/seat      |     0.39|  0.19|  48.96| 8 |      seat      |
|/swap              |     0.24|  0.12|  49.99| 3 |      swap      |
|/storage/updatemgr |     0.29|  0.28|  97.92| 12|      updatemgr |
|/storage/vtsdb     |     0.16|  0.08|  48.96| 14|      vtsdb     |
|/storage/vtsdblog  |     0.25|  0.06|  24.47| 15|      vtsdblog  |


Get-VcsaStorageLogUsage
---------------------------
The Get-VcsaStorageLogUsage will write a message output if the VCSA log storage has an insufficient amount of space.
To cleanup old storage log files, run the next command of "Clean-StorageLogDisk".

<p>Parameters:<br>
$vcenter (vCenter FQDN or IP address)<br>
$ssouser (SSO Administrator or p.Account)<br>
$ssopass (SSO Administrator or p.Account user password)</p>

```
Get-VcsaStorageLogUsage -vcenter 'vcsa-lab003.domain.local' -ssouser 'administrator@vsphere.local'
```