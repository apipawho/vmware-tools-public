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

}