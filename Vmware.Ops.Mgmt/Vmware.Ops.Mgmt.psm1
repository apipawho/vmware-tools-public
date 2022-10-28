Function Copy-VcRolesAndPermissions {

    param(
        [Parameter(Mandatory = $true)][string]$source_vcenter,
        [Parameter(Mandatory = $true)][string]$dest_vcenter,
        [Parameter(Mandatory = $true)][System.Management.Automation.PSCredential]$source_creds,
        [Parameter(Mandatory = $true)][System.Management.Automation.PSCredential]$dest_creds
    )

    #set powercli to accept multiple VM connections
    Set-PowerCLIConfiguration -DefaultVIServerMode multiple -Confirm:$false | Out-Null

    ### Variables,read inputs $source_vcenter is the srouce for pulling roles
    if (!$source_vcenter) { $source_vcenter = Read-Host -Prompt 'Please enter the SOURCE vCenter we wish to gather roles and permissions from' }
    if (!$dest_vcenter) { $dest_vcenter = Read-Host -Prompt 'Please enter the DESTINATION vCenter we wish to configure with new role and permissions' }
    if (!$source_creds) { $source_creds = Read-Host -message "Please enter the SOURCE vCenter username and password" }
    if (!$dest_creds) { $dest_creds = Read-Host -message "Please enter the DESTINATION vCenter username and password" }
    

    #connect to vCenter
    Connect-VIServer $source_vcenter -Credential $source_creds -ErrorAction Stop | Out-Null
    Connect-VIServer $dest_vcenter -Credential $dest_creds -ErrorAction Stop | Out-Null

    #Get list of roles
    $roles = Get-VIRole -Server $source_vcenter | Out-GridView -OutputMode Single -Title "Select role(s) and permissions to copy"

    #Import selected role(s)
    foreach ($role in $roles) {
        $roleif = (Get-VIRole $role -Server $dest_vcenter 2> $null)
        if ($roleif.Length -eq "1") { 
            Write-Host -Foregroundcolor DarkYellow "Role $role already exists [Skipped]"
        }
        else {
            Write-Host -foregroundcolor DarkYellow -nonewline "Creating Role $Role"
            [string[]]$privsforRoleAfromsource_vcenter = Get-VIPrivilege -Role (Get-VIRole -Name $role -server $source_vcenter) | ForEach-Object { $_.id }
            New-VIRole -name $role -Server $dest_vcenter | Out-Null
            Set-VIRole -role (Get-VIRole -Name $role -Server $dest_vcenter) -AddPrivilege (Get-VIPrivilege -id $privsforRoleAfromsource_vcenter -server $dest_vcenter) | Out-Null
            Write-Host -foregroundcolor DarkGreen " [Done]"
        }
    }
    Disconnect-VIServer * -Confirm:$false | Out-Null
}

Function Move-VMxVCvMotion {

    param(
        [Parameter(Mandatory = $false)]$source_vCenter,
        [Parameter(Mandatory = $false)]$dest_vCenter,
        [Parameter(Mandatory = $false)]$virtualMachine,
        [Parameter(Mandatory = $false)]$DstCluster,
        [Parameter(Mandatory = $false)]$DstDatastore,
        [Parameter(Mandatory = $false)]$DstVDS,
        [Parameter(Mandatory = $false)]$DstPortGroup
    )
    
    $vcCreds = Get-Credential
    
    if (!$source_vCenter) { $source_vCenter = Get-VropsList -Query VC -Creds $VcCreds | Out-GridView -OutputMode Multiple -Title "Select the SOURCE vCenter" }
    if (!$dest_vCenter) { $dest_vCenter =  Get-VropsList -Query VC -Creds $VcCreds | Out-GridView -OutputMode Multiple -Title "Select the DESTINATION vCenter" }
    Connect-ViServer -Server $source_vCenter -Credential $vcCreds -WarningAction Ignore | out-null
    write-Host -foregroundcolor Yellow "Connected to Source vCenter...$source_vCenter"
    Connect-ViServer -Server $dest_vCenter -Credential $vcCreds -WarningAction Ignore | out-null
    write-Host -foregroundcolor Yellow "Connected to Destination vCenter...$dest_vCenter"

    if (!$virtualMachine) { $virtualMachine = Get-VM -Server $source_vCenter | Out-GridView -OutputMode Multiple -Title "Select the VM to migrate" }
    if (!$DstCluster) { $DstCluster = Get-Cluster -Server $dest_vCenter | Out-GridView -OutputMode Multiple -Title "Select the destination cluster." }
    if (!$DstDatastore) { $DstDatastore = Get-Cluster -Server $dest_vCenter -Name $DstCluster | Get-Datastore | Out-GridView -OutputMode Multiple -Title "Select the datastore destination." }
    if (!$DstVDS) { $DstVDS = Get-VDSwitch -Server $dest_vCenter | Out-GridView -OutputMode Multiple -Title  "Select the distributed switch (dVS) name." }
    if (!$DstPortGroup) { $DstPortGroup = Get-VDSwitch $DstVDS -Server $dest_vCenter | Get-VDPortGroup | Out-GridView -OutputMode Multiple -Title  "Select the destination network (dVPortGroup)." }

    # Function GetPortGroupObject
    function GetPortGroupObject {
        Param(
            [Parameter(Mandatory=$True)]
            [string]$PortGroup
        )

        if (Get-VDPortGroup -Name $DstPortGroup -Server $dest_vCenter -ErrorAction SilentlyContinue) {
            return Get-VDPortGroup -Name $DstPortGroup -Server $dest_vCenter
        }
        else {
            if (Get-VirtualPortGroup -Name $DstPortGroup -Server $dest_vCenter -ErrorAction SilentlyContinue) {
                return Get-VirtualPortGroup -Name $DstPortGroup -Server $dest_vCenter
            }
            else {
                Write-Host "The PorGroup '$DstPortGroup' doesn't exist in the destination vCenter"
                exit
            }
        }
    }

    $sourcedVswtich = Get-VM $virtualMachine -server $source_vCenter | Get-VDSwitch

    if ($sourcedVswtich.Version -lt $DstVDS.Version) {
        Write-Host -ForegroundColor Red "The destination dVswitch is at a greater version ("$DstVDS.Version") then the source dVswitch ("$sourcedVswtich.Version")."
        Write-Host -ForegroundColor Red "Please upgrade the source dVswitch $sourcedVswtich to a compatible version and re-run the migration."
        Write-Host -ForegroundColor Red "The script will now exit."
        Exit

    } else {

    # vMotion
    $vm = Get-VM $virtualMachine
    $destination = Get-VMHost -Location $DstCluster | Get-Random
    $networkAdapter = Get-NetworkAdapter -VM $virtualMachine
    $destinationPortGroup = GetPortGroupObject -PortGroup $DstPortGroup
    $destinationDatastore = Get-Datastore $DstDatastore

    Write-Host "Migrating " -NoNewline
    Write-Host $virtualMachine -ForegroundColor Cyan -NoNewline
    Write-Host " to " -NoNewline
    Write-Host $destination -ForegroundColor Cyan -NoNewline
    Write-Host " on VMNetwork " -NoNewline
    Write-Host $DstPortGroup -ForegroundColor Cyan -NoNewline
    Write-Host " on datastore " -NoNewline
    Write-Host $DstDatastore -ForegroundColor Cyan

    Read-Host -Prompt "Press ENTER to continue or CTRL+C to quit"

    $vm | Move-VM -Destination $destination -NetworkAdapter $networkAdapter -PortGroup $destinationPortGroup -Datastore $destinationDatastore | out-null

    ####################################################################################
    # Display VM information after vMotion
    write-host -foregroundcolor Cyan "`nVM is now running on:"

    Get-VM $virtualMachine | Get-NetworkAdapter | Select-Object @{N="VM Name";E={$_.Parent.Name}},@{N="Cluster";E={Get-Cluster -VM $_.Parent}},@{N="ESXi Host";E={Get-VMHost -VM $_.Parent}},@{N="Datastore";E={Get-Datastore -VM $_.Parent}},@{N="Network";E={$_.NetworkName}} | Format-List

    }
    
####################################################################################
# Disconnect
Disconnect-VIServer -Server * -Force -Confirm:$false

}

Function Test-Multipath {
    <#
    .SYNOPSIS
        Test multipath ESXi LUN paths
    .DESCRIPTION
        Test multipath ESXi LUN paths for proper and consistent configuration across ESXi hosts.
    .EXAMPLE
        test-multipath -vcenter vCentername
        test-multipath -vcenter vCentername -csvout c:\tmp\file.csv
    #>
    
    param (
        [parameter(Mandatory = $true)]$vcenter,
        [parameter(Mandatory = $false)]$csvout
    )

    #confirm/enter credentials
    if (!$vc_creds) {
        $vc_creds = get-credential
    }

    #connect to VC
    Connect-ViServer $vcenter -credential $vc_creds

    $clusters = get-cluster
    $results = @()
    foreach ($cluster in $clusters) {
        $datastores = get-cluster $cluster | get-datastore
        foreach ($datastore in $datastores) {

            if ($datastore.ExtensionData.Summary.MultipleHostAccess -eq "True") {
                write-host checking $datastore on all hosts in the cluster $cluster
                $results += Get-Datastore $datastore | Get-ScsiLun | Select-Object VMHost, CanonicalName, @{Name = 'Active Paths'; Expression = { ($_ | Get-ScsiLunPath).SanID.Count } } | sort-object -property VMHost
            }
        }
    }

    Disconnect-ViServer $vcenter -confirm:$false

    if (!$csvout) {
        $results
    }
    else {
        $results | export-csv -NoTypeInformation -path $csvout
        write-host outputted results to path $csvout
    }
}

Function Update-EsxiRootPwd {
    <#
        .SYNOPSIS
            This function updates the ESXi root password on all ESXi hosts in all vCenters collected from vROps or a CSV file unless specified as a parameter for only 1 vCenter.
        .DESCRIPTION
            Update ESXi root password.
        .EXAMPLE
            Update-EsxiRootPwd -vcenter vcsa-lab000.domain.local        
    #>

    param(
        [Parameter(Mandatory = $false)][string]$vcenter,
        [Parameter(Mandatory = $false)][secureString]$rootPassword
    )

    $vc_creds = Get-Credential -Message "Enter Your AD Username and Password"
    
    if (!$vcenter) { $vcenter = Get-VropsList -Query VC -Creds $vc_creds }
    if (!$vcenter) { $vCenter_List = $vcenter | Out-GridView -OutputMode Multiple -Title "Select vCenter" }
    $Vcenter_List = $vcenter

    $rootUsr = "root"
    Function New-RandomPassword {
       param (
           [Parameter(Mandatory)]
           [ValidateRange(4,[int]::MaxValue)]
           [int] $length,
           [int] $upper = 1,
           [int] $lower = 1,
           [int] $numeric = 1,
           [int] $special = 1
       )
       if($upper + $lower + $numeric + $special -gt $length) {
           throw "number of upper/lower/numeric/special char must be lower or equal to length"
       }
       $uCharSet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
       $lCharSet = "abcdefghijklmnopqrstuvwxyz"
       $nCharSet = "0123456789"
       $sCharSet = "/*-+,!?=()@;:._"
       $charSet = ""
       if($upper -gt 0) { $charSet += $uCharSet }
       if($lower -gt 0) { $charSet += $lCharSet }
       if($numeric -gt 0) { $charSet += $nCharSet }
       if($special -gt 0) { $charSet += $sCharSet }
       
       $charSet = $charSet.ToCharArray()
       $rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
       $bytes = New-Object byte[]($length)
       $rng.GetBytes($bytes)
    
       $result = New-Object char[]($length)
       for ($i = 0 ; $i -lt $length ; $i++) {
           $result[$i] = $charSet[$bytes[$i] % $charSet.Length]
       }
       $password = (-join $result)
       $valid = $true
       if($upper   -gt ($password.ToCharArray() | Where-Object {$_ -cin $uCharSet.ToCharArray() }).Count) { $valid = $false }
       if($lower   -gt ($password.ToCharArray() | Where-Object {$_ -cin $lCharSet.ToCharArray() }).Count) { $valid = $false }
       if($numeric -gt ($password.ToCharArray() | Where-Object {$_ -cin $nCharSet.ToCharArray() }).Count) { $valid = $false }
       if($special -gt ($password.ToCharArray() | Where-Object {$_ -cin $sCharSet.ToCharArray() }).Count) { $valid = $false }
    
       if(!$valid) {
            $password = Get-RandomPassword $length $upper $lower $numeric $special
       }
       return $password
    }

    if (!$rootPwd) { $rootPwd = New-RandomPassword 8 }
    if (!$rootPwd) { $rootPwd = ($rootPassword | ConvertFrom-SecureString -AsPlainText) }
    
    #####################
    # static variables  #
    #####################
    $VmHostCount = 1
    $VcCount = 1
    
    #####################
    # user confirmation #
    #####################
    Write-Host -ForegroundColor Green "Preparing to update the root password on the following $($Vcenter_List.count) vCenters"
    Start-Sleep 2
    $vCenter_List
    Write-Host "Would you like to continue:" -ForegroundColor Yellow -NoNewline
    $ReadHost = Read-Host " ( y / n ) " 
    Switch ($ReadHost) { 
           Y {
                  ################################################
                  # connect to each vCenter/disconnect when done #
                  ################################################
                  foreach ($vc in $vCenter_List) {
                         Connect-ViServer -Server $vc -Credential $vc_creds -WarningAction SilentlyContinue -ErrorAction Stop | out-null
                         Write-Host -ForegroundColor Green "Changing root password on ($vc) `($VcCount of $($vCenter_List.count)`)"
                         $VmHosts = Get-VmHost | Where-Object { $_.ConnectionState -eq "Connected" -or $_.ConnectionState -eq "Maintenance" }
                         ################################
                         # Update password on each host #
                         ################################
                         foreach ($VmHost in $VmHosts) {
                                Write-Host -NoNewline "($VmHost) `($VmHostCount of $($VmHosts.count)`) has completed..."
                                $EsxCli = Get-EsxCli -VmHost $VmHost -v2 
                                $EsxCli.system.account.set.Invoke(@{id = $rootUsr; password = $rootPwd; passwordconfirmation = $rootPwd })
                                $VmHostCount++
                         }
                         $DcHosts = Get-VmHost | Where-Object { $_.ConnectionState -eq "Disconnected" -or $_.ConnectionState -eq "NotResponding " }
                         $DcList += $DcHosts
                         Disconnect-ViServer -confirm:$false *
                         $VcCount++
                         $VmHostCount = 1
                  }
                  Write-Host ""
                  Write-Host -ForegroundColor Yellow "The following ESXi hosts were unable to be updated due to being disconnected or non-responsive."
                  foreach ($DcHost in $DcList) {
                         $VcDnsLookup = (Resolve-DnsName $($DcHost.ExtensionData.Summary.ManagementServerIp)).NameHost
                         Write-Host -ForegroundColor Yellow -NoNewLine "[ $VcDnsLookup`:$($DcHost.Name) ] " 
                         Write-Host "is disconnected or not-responsive - unable to update password"
                  }
           }
           ##################################
           # if confirmation is false exit  #
           ##################################
           N { Write-Host -ForegroundColor Red "Exiting without making changes" } 
           Default { Write-Host "Please Enter Y or N" } 
        }   
    Write-Host 'Please record the new password in KeePass ' -ForegroundColor Yellow -NoNewline
    Write-Host -ForegroundColor Cyan $rootPwd

    Disconnect-VIServer * -Confirm:$false
}

Function Set-EsxiNtpSource {
    <#
    .SYNOPSIS
        Set NTP Source Servers for ESXi hosts
    .DESCRIPTION
        Stop NTP service temporarily.
        Clear current NTP Source Servers.
        Add current NTP Source Servers.
        Set NTP Service Policy to "on" (Start and stop with host).
        Start NTP Service on ESXi hosts.
        Test NTP services with newly configured NTP Source(s).
    .EXAMPLE
        Set-EsxiNtpSource -vCenter 'vcenter.fqdn.com'
        Set-EsxiNtpSource -vCenter 'vcenter.fqdn.com' -ntpSource "8.8.8.8"
    #>

    param (
        [parameter(Mandatory = $true)]$vCenter,
        [parameter(Mandatory = $false)]$ntpSource
    )
    
    if (!$vCenter) { Read-Host "Please enter the FQDN of the vCenter of the ESXi hosts to update NTP settings." }
    $vc_creds = Get-Credential

    #Connect to vCenter Server
    Connect-VIServer $vCenter -Credential $vc_creds -WarningAction Ignore | Out-Null

    #NTP Source Servers
    if (!$ntpSource) { $ntpSource = "8.8.8.8" }

    #Set NTP settings for hosts
    $EsxHosts = Get-Cluster | Get-VMHost | Where-Object { $_.ConnectionState -eq "Connected" -and $_.CnnectionState -ne "NotResponding" }
        foreach($EsxHost in $EsxHosts){
            $esxcli = Get-EsxCli -V2 -VMHost $EsxHost
            $current_ntpSources = @($EsxHost | Get-VMHostNtpServer)
            $curSources = [string]::Join('|',$current_ntpSources)
            $ntpSources = [string]::Join('|',$ntpSource)

            if ($esxcli.system.version.get.Invoke().Version -eq "6.7.0") {
                $EsxHost_id = ($EsxHost | Select-Object id).Id.Trim("HostSystem-host")
                $timeService = "HostDateTimeSystem-dateTimeSystem-" + $EsxHost_id
                $esxHostTimeService = Get-View -id $timeService

                if ($ntpSources -eq $curSources) {
                    Write-Host "NTP Source is already up-to-date! " -NoNewline -ForegroundColor Green
                    Write-Host "Skipping $EsxHost" -ForegroundColor Yellow
                }else{
                    #stop ntp service on host
                    Write-Host "Stopping NTP service on $EsxHost" -ForegroundColor Red
                    $ntpService = $EsxHost | Get-VMHostService | Where-Object {$_.key -eq "ntpd"}
                    Stop-VMHostService -HostService $ntpService -confirm:$false | Out-Null
                    Start-Sleep 2
                    
                    #clear current NTP servers
                    Write-Host "Clearing current NTP source(s) on $EsxHost" -ForegroundColor DarkMagenta
                    $current_ntpSources = @($EsxHost | Get-VMHostNtpServer)
                    foreach ($current_ntpSource in $current_ntpSources){
                        Remove-VMHostNtpServer -ntpserver $current_ntpSource -vmhost $EsxHost -confirm:$false | Out-Null
                    }
                    Start-Sleep 2

                    #and set new NTP servers
                    Write-Host "Adding NTP source(s) on $EsxHost" -ForegroundColor Cyan
                    Add-VMHostNtpServer -ntpserver $ntpSource -vmhost $EsxHost -confirm:$false | Out-Null
                    Start-Sleep 2
            
                    #set service policy to start and stop with host
                    Write-Host "Setting NTP service policy to 'on' on $EsxHost" -ForegroundColor Cyan
                    Set-VMHostService -HostService $ntpService -Policy "on" -confirm:$false | Out-Null
                    Start-Sleep 2

                    #start NTP on vmhost
                    Write-Host "Starting NTP service on $EsxHost" -ForegroundColor Green
                    Start-VMHostService -HostService $ntpService -confirm:$false | Out-Null
                    Start-Sleep 2
                    
                    #test NTP time service
                    Write-Host "Testing NTP service on $EsxHost" -ForegroundColor Green
                    $esxHostTimeService.RefreshDateTimeSystem()
                    $getDate = (get-date).ToUniversalTime().ToString("MMddyy HH:mm:ss")
                    $getEesxHostDate = ($esxHostTimeService.QueryDateTime()).ToUniversalTime().ToString("MMddyy HH:mm:ss")
                        if ($getDate -eq $getEesxHostDate) {
                            Write-Host "NTP source(s) and time are working properly." -ForegroundColor Green -NoNewline
                            Write-Host "Time is sycnrhonized." -ForegroundColor Green 
                        }else{
                            Write-Host "Please check that the NTP service is running on the host."
                        }
                }
            }else{
                foreach($EsxHost in $EsxHosts){
                    $EsxHost_id = ($EsxHost | Select-Object id).Id.Trim("HostSystem-host")
                    $timeService = "HostDateTimeSystem-dateTimeSystem-" + $EsxHost_id
                    $esxHostTimeService = Get-View -id $timeService
                    $esxcli = Get-EsxCli -V2 -VMHost $EsxHost
                    $current_ntpSources = @($EsxHost | Get-VMHostNtpServer)
                    $curSources = [string]::Join('|',$current_ntpSources)
                    $ntpSources = [string]::Join('|',$ntpSource)
                    
                    if ($ntpSources -eq $curSources) {
                        Write-Host "NTP Source is already up-to-date! " -NoNewline -ForegroundColor Green
                        Write-Host "Skipping $EsxHost" -ForegroundColor Yellow
                    }else{
                    #stop ntp service on host
                    Write-Host "Stopping NTP service on $EsxHost" -ForegroundColor Red
                    $ntpService = $EsxHost | Get-VMHostService | Where-Object {$_.key -eq "ntpd"}
                    Stop-VMHostService -HostService $ntpService -confirm:$false | Out-Null
                    Start-Sleep 2
                    
                    #clear current NTP servers
                    Write-Host "Clearing current NTP source(s) on $EsxHost" -ForegroundColor DarkMagenta
                    $current_ntpSources = @($EsxHost | Get-VMHostNtpServer)
                    foreach ($current_ntpSource in $current_ntpSources){
                        Remove-VMHostNtpServer -ntpserver $current_ntpSource -vmhost $EsxHost -confirm:$false | Out-Null
                    }
                    Start-Sleep 2
            
                    #and set new NTP servers
                    Write-Host "Adding NTP source(s) on $EsxHost" -ForegroundColor Cyan
                    $esxcli.system.ntp.set.Invoke(@{server = $ntpSource}) | Out-Null
                    Start-Sleep 2
            
                    #set service policy to start and stop with host
                    Write-Host "Setting NTP service policy to 'on' on $EsxHost" -ForegroundColor Cyan
                    Set-VMHostService -HostService $ntpService -Policy "on" -confirm:$false | Out-Null
                    Start-Sleep 2
            
                    #start NTP on vmhost
                    Write-Host "Starting NTP service on $EsxHost" -ForegroundColor Green
                    Start-VMHostService -HostService $ntpService -confirm:$false | Out-Null
                    Start-Sleep 2
                }
                #Test NTP settings for all hosts
                foreach($EsxHost in $EsxHosts){
                    $EsxHost_id = ($EsxHost | Select-Object id).Id.Trim("HostSystem-host")
                    $timeService = "HostDateTimeSystem-dateTimeSystem-" + $EsxHost_id
                    $esxHostTimeService = Get-View -id $timeService
                    $esxcli = Get-EsxCli -V2 -VMHost $EsxHost
            
                    #test NTP time service
                    Write-Host "Testing NTP service on $EsxHost ..." -ForegroundColor DarkYellow
                    $esxHostTimeService.RefreshDateTimeSystem()
                    $getDate = (get-date).ToUniversalTime().ToString("MMddyy HH:mm:ss")
                    $getEesxHostDate = ($esxHostTimeService.QueryDateTime()).ToUniversalTime().ToString("MMddyy HH:mm:ss")
                        if ($getDate -eq $getEesxHostDate) {
                            Write-Host "NTP source(s) and time are working properly." -ForegroundColor Green -NoNewline
                            Write-Host "Time is sycnrhonized." -ForegroundColor Green 
                        }else{
                            $esxHostTimeService.RefreshDateTimeSystem()
                            $testEsxHostTimeService = $esxHostTimeService.TestTimeService()
                                if ($testEsxHostTimeService.WorkingNormally -ne 'True' ) {
                                    Write-Host ($esxHostTimeService.TestTimeService()).Report -ForegroundColor Red
                                }else{
                                    Write-Host ($esxHostTimeService.TestTimeService()).Report -ForegroundColor Cyan
                                }
                        }
                }
                }
            }
        }
    Disconnect-VIServer * -Confirm:$false | Out-Null
}

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

Function Set-VcsaNtpSource {
    <#
    .SYNOPSIS
        Set NTP Source Servers for VMware VCSA
    .DESCRIPTION
        
    .EXAMPLE
        Set-VcsaNtpSource -vcenter 'vcenter.fqdn.com'
        Set-VcsaNtpSource -vcenter 'vcenter.fqdn.com' -ntpSource "8.8.8.8"
    #>

    param(
          [Parameter(Mandatory = $true)][string]$vcenter,
          [parameter(Mandatory = $false)]$ntpSource,
          [Parameter(Mandatory = $true)][string]$vc_user,
          [Parameter(Mandatory = $true)][secureString]$vc_pass
    )

    # Auth and NTP variables
    $ErrorActionPreference = "Ignore"
    if (!$vcenter) { $vcenter = Read-Host  "Please enter vCenter name" }
    if (!$vc_user) { $vc_user = Read-Host  "Please enter an administrator username (administrator@vsphere.local)" }
    if (!$vc_pass) { $vc_pass = Read-Host  | ConvertFrom-SecureString -AsPlainText -Force "Please enter the administrator password" }
    #NTP Source Servers
    if (!$ntpSource) { $ntpSource = '"8.8.8.8"' }
    
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

    #Test for VCSA 6.7.* or VCSA 7.0.* API and get API Session ID
    if ($null -eq $sessionId) {
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

        $current_ntpSources = ($NtpInfo.Content | ConvertFrom-Json).value
        $curSources = [string]::Join('|',$current_ntpSources)
        $ntpSources = [string]::Join('|',$ntpSource)

        if ($ntpSources -notin $curSources) {
            Write-host "The NTP Source(s) for $vcenter is different than the standard." -ForegroundColor Yellow

            Write-Host "Updating NTP Source on $vcenter..." -Foreground Cyan -NoNewline

            $ntpSourceBody = "{`n    `"servers`": [ $ntpSources ]`n}"
            
            $headers.Add("Content-Type", "application/json")
            $ntpSourceSet = Invoke-WebRequest $NtpUrl -Method 'PUT' -Headers $headers -Body $ntpSourceBody -SkipCertificateCheck

            if ($null -eq $ntpSourceSet ){
                Write-Host "Please check configurations for this module. No payload was sent to be modified."
            }
            elseif ($ntpSourceSet.StatusDescription -eq 'OK') {
                Write-Host "NTP Source(s) has been correctly updated to $ntpSource." -ForegroundColor DarkGreen
            }
        }
        else { Write-host "VCSA NTP Source is correctly configured!" -ForegroundColor "Green" }

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
        Write-Host "VCSA API Version is 7.0..."
        $NtpUrl = $BaseUrl + "api/appliance/ntp"
        # Return NTP Information
        $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
        $headers.Add("vmware-api-session-id", $sessionId)

        $NtpInfo = Invoke-WebRequest $NtpUrl -Method 'GET' -Headers $headers -SkipCertificateCheck
        $current_ntpSources = $NtpInfo.Content | ConvertFrom-Json
        $curSources = [string]::Join('|',$current_ntpSources)
        $ntpSources = [string]::Join('|',$ntpSource)

        if ($ntpSources -notin $curSources) {
            Write-host "The NTP Source(s) for $vcenter is different than the standard." -ForegroundColor Yellow

            Write-Host "Updating NTP Source on $vcenter..." -Foreground Cyan -NoNewline

            $ntpSourceBody = "{`n    `"servers`": [ $ntpSources ]`n}"
            
            $headers.Add("Content-Type", "application/json")
            $ntpSourceSet = Invoke-WebRequest $NtpUrl -Method 'PUT' -Headers $headers -SkipCertificateCheck -Body $ntpSourceBody
            
            if ($ntpSourceSet.StatusCode -eq "204"){
                Write-Host "NTP Source(s) has been correctly updated to $ntpSource." -ForegroundColor DarkGreen
            }else{
                Write-Host "NTP Source(s) have not been updated." -ForegroundColor Red
                Write-Host $ntpSourceSet.Content -ForegroundColor Red
            }
        }
        else { Write-host "VCSA NTP Source is correctly configured!" -ForegroundColor "Green" }

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

Function Get-ContentLibrary {
<#
    .NOTES
    ===========================================================================
    Created by:    William Lam
    Organization:  VMware
    Blog:          www.virtuallyghetto.com
    Twitter:       @lamw
    ===========================================================================
    .DESCRIPTION
        This function lists all available vSphere Content Libaries
    .PARAMETER LibraryName
        The name of a vSphere Content Library
    .EXAMPLE
        Get-ContentLibrary
    .EXAMPLE
        Get-ContentLibrary -LibraryName Test
#>
    param(
        [Parameter(Mandatory=$false)][String]$LibraryName
    )

    $contentLibraryService = Get-CisService com.vmware.content.library
    $LibraryIDs = $contentLibraryService.list()

    $results = @()
    foreach($libraryID in $LibraryIDs) {
        $library = $contentLibraryService.get($libraryID)

        # Use vCenter REST API to retrieve name of Datastore that is backing the Content Library
        $datastoreService = Get-CisService com.vmware.vcenter.datastore
        $datastore = $datastoreService.get($library.storage_backings.datastore_id)

        if($library.publish_info.published) {
            $published = $library.publish_info.published
            $publishedURL = $library.publish_info.publish_url
            $externalReplication = $library.publish_info.persist_json_enabled
        } else {
            $published = $library.publish_info.published
            $publishedURL = "N/A"
            $externalReplication = "N/A"
        }

        if($library.subscription_info) {
            $subscribeURL = $library.subscription_info.subscription_url
            $published = "N/A"
        } else {
            $subscribeURL = "N/A"
        }

        if(!$LibraryName) {
            $libraryResult = [pscustomobject] @{
                Id = $library.Id;
                Name = $library.Name;
                Type = $library.Type;
                Description = $library.Description;
                Datastore = $datastore.name;
                Published = $published;
                PublishedURL = $publishedURL;
                JSONPersistence = $externalReplication;
                SubscribedURL = $subscribeURL;
                CreationTime = $library.Creation_Time;
            }
            $results+=$libraryResult
        } else {
            if($LibraryName -eq $library.name) {
                $libraryResult = [pscustomobject] @{
                    Name = $library.Name;
                    Id = $library.Id;
                    Type = $library.Type;
                    Description = $library.Description;
                    Datastore = $datastore.name;
                    Published = $published;
                    PublishedURL = $publishedURL;
                    JSONPersistence = $externalReplication;
                    SubscribedURL = $subscribeURL;
                    CreationTime = $library.Creation_Time;
                }
                $results+=$libraryResult
            }
        }
    }
    $results
}

Function Get-ContentLibraryItems {
<#
    .NOTES
    ===========================================================================
    Created by:    William Lam
    Organization:  VMware
    Blog:          www.virtuallyghetto.com
    Twitter:       @lamw
    ===========================================================================
    .DESCRIPTION
        This function lists all items within a given vSphere Content Library
    .PARAMETER LibraryName
        The name of a vSphere Content Library
    .PARAMETER LibraryItemName
        The name of a vSphere Content Library Item
    .EXAMPLE
        Get-ContentLibraryItems -LibraryName Test
    .EXAMPLE
        Get-ContentLibraryItems -LibraryName Test -LibraryItemName TinyPhotonVM
#>
    param(
        [Parameter(Mandatory=$true)][String]$LibraryName,
        [Parameter(Mandatory=$false)][String]$LibraryItemName
    )

    $contentLibraryService = Get-CisService com.vmware.content.library
    $LibraryIDs = $contentLibraryService.list()

    $results = @()
    foreach($libraryID in $LibraryIDs) {
        $library = $contentLibraryService.get($libraryId)
        if($library.name -eq $LibraryName) {
            $contentLibraryItemService = Get-CisService com.vmware.content.library.item
            $itemIds = $contentLibraryItemService.list($libraryID)

            foreach($itemId in $itemIds) {
                $item = $contentLibraryItemService.get($itemId)

                if(!$LibraryItemName) {
                    $itemResult = [pscustomobject] @{
                        Name = $item.name;
                        Id = $item.id;
                        Description = $item.description;
                        Size = $item.size
                        Type = $item.type;
                        Version = $item.version;
                        MetadataVersion = $item.metadata_version;
                        ContentVersion = $item.content_version;
                    }
                    $results+=$itemResult
                } else {
                    if($LibraryItemName -eq $item.name) {
                        $itemResult = [pscustomobject] @{
                            Name = $item.name;
                            Id = $item.id;
                            Description = $item.description;
                            Size = $item.size
                            Type = $item.type;
                            Version = $item.version;
                            MetadataVersion = $item.metadata_version;
                            ContentVersion = $item.content_version;
                        }
                        $results+=$itemResult
                    }
                }
            }
        }
    }
    $results
}

Function Get-ContentLibraryItemFiles {
<#
    .NOTES
    ===========================================================================
    Created by:    William Lam
    Organization:  VMware
    Blog:          www.virtuallyghetto.com
    Twitter:       @lamw
    ===========================================================================
    .DESCRIPTION
        This function lists all item files within a given vSphere Content Library
    .PARAMETER LibraryName
        The name of a vSphere Content Library
    .PARAMETER LibraryItemName
        The name of a vSphere Content Library Item
    .EXAMPLE
        Get-ContentLibraryItemFiles -LibraryName Test
    .EXAMPLE
        Get-ContentLibraryItemFiles -LibraryName Test -LibraryItemName TinyPhotonVM
#>
    param(
        [Parameter(Mandatory=$true)][String]$LibraryName,
        [Parameter(Mandatory=$false)][String]$LibraryItemName
    )

    $contentLibraryService = Get-CisService com.vmware.content.library
    $libraryIDs = $contentLibraryService.list()

    $results = @()
    foreach($libraryID in $libraryIDs) {
        $library = $contentLibraryService.get($libraryId)
        if($library.name -eq $LibraryName) {
            $contentLibraryItemService = Get-CisService com.vmware.content.library.item
            $itemIds = $contentLibraryItemService.list($libraryID)
            $DatastoreID = $library.storage_backings.datastore_id.Value
            $Datastore = get-datastore -id "Datastore-$DatastoreID"

            foreach($itemId in $itemIds) {
                $itemName = ($contentLibraryItemService.get($itemId)).name
                $contentLibraryItemFileSerice = Get-CisService com.vmware.content.library.item.file
                $files = $contentLibraryItemFileSerice.list($itemId)
                $contentLibraryItemStorageService = Get-CisService com.vmware.content.library.item.storage

                foreach($file in $files) {
                    if($contentLibraryItemStorageService.get($itemId, $($file.name)).storage_backing.type -eq "DATASTORE"){
                        $filepath = $contentLibraryItemStorageService.get($itemId, $($file.name)).storage_uris.AbsolutePath.split("/")[5..7] -join "/"
                        $fullfilepath = "[$($datastore.name)] $filepath"
                    }
                    else{
                        $fullfilepath = "UNKNOWN"
                    }

                    if(!$LibraryItemName) {
                        $fileResult = [pscustomobject] @{
                            Name = $file.name;
                            Version = $file.version;
                            Size = $file.size;
                            Stored = $file.cached;
                            Path = $fullfilepath;
                        }
                        $results+=$fileResult
                    } else {
                        if($itemName -eq $LibraryItemName) {
                            $fileResult = [pscustomobject] @{
                                Name = $file.name;
                                Version = $file.version;
                                Size = $file.size;
                                Stored = $file.cached;
                                Path = $fullfilepath;
                            }
                            $results+=$fileResult
                        }
                    }
                }
            }
        }
    }
    $results
}

Function Get-EsxiNtpServiceRefresh {
    
    $EsxHosts = Get-VMHost | Where-Object { $_.ConnectionState -eq "Connected" -and $_.CnnectionState -ne "NotResponding" } | Sort-Object
    foreach($EsxHost in $EsxHosts){
        $EsxHost_id = ($EsxHost | Select-Object id).Id.Trim("HostSystem-host")
        $timeService = "HostDateTimeSystem-dateTimeSystem-" + $EsxHost_id
        $esxHostTimeService = Get-View -id $timeService
    
        #test NTP time service
        Write-Host "Refreshing NTP service on " -ForegroundColor DarkYellow -NoNewline
        Write-Host "$EsxHost ..." -ForegroundColor DarkCyan -NoNewline
        $esxHostTimeService.RefreshDateTimeSystem()
        Write-Host " [DONE]" -ForegroundColor DarkGreen
    }
}