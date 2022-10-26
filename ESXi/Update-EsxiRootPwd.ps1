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
}