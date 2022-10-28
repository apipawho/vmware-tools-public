Function Get-VcsaCertStatus {
    param(
        [Parameter(Mandatory = $false)][string]$mgmt_vcenter,
        [Parameter(Mandatory = $false)][string]$rootPass,
        [Parameter(Mandatory = $false)][string]$vcenter
    )

    if (!$rootPass) { $rootPass = Read-Host "Please enter the root password for VCSA VM" }

    $vm = Get-Vm | Where-Object { $_.Name -like "$vcenter*" -and $_.PowerState -eq "PoweredOn" }

    if ($vm) {
        Invoke-VMScript -ScriptText 'for i in $(/usr/lib/vmware-vmafd/bin/vecs-cli store list); do echo STORE $i; sudo /usr/lib/vmware-vmafd/bin/vecs-cli entry list --store $i --text | egrep "Alias|Not After"; done' -vm $vm -GuestUser "root" -GuestPassword $rootPass
    } else {
        Write-Host "vCenter ($vcenter) is not managed by $mgmt_vcenter." -ForegroundColor Yellow
        Write-Host "Please provide the vCenter to where $vcenter is being managed and re-run the script."
        Disconnect-VIServer $mgmt_vcenter -Confirm:$false | Out-Null
    }

}