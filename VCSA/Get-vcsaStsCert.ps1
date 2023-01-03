Function Get-vcsaStsCert {
    param(
        [Parameter(Mandatory = $true)][string]$mgmt_vcenter,
        [Parameter(Mandatory = $false)][string]$rootPass,
        [Parameter(Mandatory = $true)][string]$vcenter
    )

    $vc_creds = Get-Credential -Message "Enter Your AD Username and Password"
    $rootPass = Read-Host "Please enter the root password for VCSA VM"

    Connect-VIServer $mgmt_vcenter -Credential $vc_creds -ErrorAction Stop | Out-Null
    $vm = Get-Vm | Where-Object { $_.Name -like "$vcenter*" -and $_.PowerState -eq "PoweredOn" }

    if ($vm) {
        #Checking STS Cert on VCSA
        Write-host "Checking STS Cert..." -ForegroundColor Yellow -NoNewLine 
        Invoke-VMScript -ScriptText "python /tmp/checksts.py" -vm $vm -GuestUser "root" -GuestPassword $rootPass
    }
    else {
        Write-Host "vCenter ($vcenter) is not managed by $mgmt_vcenter." -ForegroundColor Yellow
        Write-Host "Please provide the vCenter to where $vcenter is being managed and re-run the script."
        Disconnect-VIServer $mgmt_vcenter -Confirm:$false | Out-Null
    }
}