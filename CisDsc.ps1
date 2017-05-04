function Install-CisDscConfiguration {

    param(
        [Parameter(Mandatory=$true)][string[]]$ComputerName,
        [Parameter(Mandatory=$true)][string]$PullServerName,
        [int]$Port = 8080,
        [string]$InputDsc = "$env:SystemDrive\DSC\",
        [switch]$Force
    )

    $VerboseState = $VerbosePreference -ne "SilentlyContinue"
    $ForceState = $Force.IsPresent
    $RestartArray = New-Object System.Collections.ArrayList
    $Guid = [guid]::NewGuid()
    $Credential = Get-Credential -Message "Please provide a valid credential to apply DSC settings. Make sure this credential has access to \\files.ad.brown.edu." -UserName "ad\adm_yqin"

    # check prerequisite WMF 5
    try {
        foreach ($comp in $ComputerName) {
            if ($(Invoke-Command -ComputerName $comp {Get-WmiObject -Class Win32_OperatingSystem | % Caption}) -notlike "Microsoft Windows Server 201*") {
                Write-Warning "Machine $comp does not have a supported OS version."
                continue
            }

            # EXPERIMENTAL: install WMF 5 for Server 2012 machines; ideally WMF 5 should have been installed manually
            $ver = $(Invoke-Command -ComputerName $comp {$PSVersionTable.PSVersion | % Major})
            if ($ver -lt 5) {
                Write-Verbose "Installing WMF 5 for $comp..."
                $rand = [string][guid]::NewGuid()
                Invoke-Command -ComputerName $comp {if (-not $(Test-Path "$env:SystemDrive\dsctemp")) {mkdir "$env:SystemDrive\dsctemp"}}
                Invoke-Command -ComputerName $comp {New-SmbShare -Name "dsctemp$args" -Path "$env:SystemDrive\dsctemp" -FullAccess "AD\adm_yqin"} -ArgumentList $rand
                Copy-Item -Path "\\files\dfs\CISWindows\Software\DSCBackup\WMF5-x64.msu" -Destination "\\$comp\dsctemp$rand\"
                Invoke-Command -ComputerName $comp {Get-SmbShare -Name "dsctemp*" | Remove-SmbShare -Confirm:$false}
                # TODO: this line of code is known to be buggy; cannot invoke wusa remotely
                Invoke-Command -ComputerName $comp {wusa "$env:SystemDrive\dsctemp\WMF5-x64.msu" /quiet /norestart}
                $RestartArray += $comp
            } else {
                Write-Verbose "$comp has compatible WMF version $ver."
            }
        }
    } catch {
        Write-Warning "CRITICAL: Failed to check target WMF version - please check network and permission!"
        return
    }

    # EXPERIMENTAL: wait for machines that just installed WMF 5 to restart
    if ($RestartArray) {  
        while (Get-Process -ComputerName $RestartArray | Where-Object ProcessName -eq "wusa") {
            Write-Verbose "Stilling installing..."
            Start-Sleep -s 10
        }
        Write-Verbose "Restarting $RestartArray..."
        Restart-Computer $RestartArray -Force:$ForceState -Wait -For WinRM
    }

    # generate configuration for DSC local configuration manager
    Write-Verbose "Generating meta mof..."
    . $InputDsc\LCM_HttpPull.ps1
    LCM_HttpPull -ComputerName $ComputerName -Guid $Guid -PullServerName $PullServerName -Port $Port -OutputPath "$InputDsc\Config"


    Set-DscLocalConfigurationManager -ComputerName $ComputerName -Path "$InputDsc\Config" -Force:$ForceState -Verbose:$VerboseState

    # generate configuration from template
    Write-Verbose "Generating mof from Template..."
    . $InputDsc\Template.ps1
    # TODO: this should have been configured to encrypt user credential: https://blogs.msdn.microsoft.com/powershell/2014/01/31/want-to-secure-credentials-in-windows-powershell-desired-state-configuration/
    $cred = @{
        AllNodes = @(
            @{
                NodeName = $ComputerName
                PsDscAllowDomainUser = $true
                PsDscAllowPlainTextPassword = $true
            }
        )
    }
    Template -ComputerName $ComputerName -Credential $credential -OutputPath "$InputDsc\Config" -ConfigurationData $cred

    # update configuration
    $Source = "$InputDsc\Config\$comp.mof"

    $Dest = "$env:ProgramFiles\WindowsPowershell\DscService\Configuration\$Guid.mof"
    Copy-Item -Path $Source -Destination $Dest -Verbose:$VerboseState
    New-DscChecksum $Dest -Verbose:$VerboseState
    
    $Dest = "${env:ProgramFiles(x86)}\WindowsPowershell\DscService\Configuration\$Guid.mof"
    Copy-Item -Path $Source -Destination $Dest -Verbose:$VerboseState
    New-DscChecksum $Dest -Verbose:$VerboseState

    Update-DscConfiguration -ComputerName $ComputerName -Wait -Verbose:$VerboseState
}

function Install-CisDscPullServer {
    param (
        [Parameter(Mandatory=$true)][string[]]$ComputerName,
        [int]$PullPort = 8080,
        [int]$CompliancePort = 8081,
        [string]$InstallDest = $env:SystemDrive
    )

    $VerboseState = $VerbosePreference -ne "SilentlyContinue"

    if ($(Get-DscResource | Select-Object -ExpandProperty ModuleName -Unique) -notcontains "xPSDesiredStateconfiguration", "xSystemSecurity", "xRemoteDesktopAdmin") {
        Write-Verbose "Using backup files..."
        Copy-Item -Path "\\files\dfs\CISWindows\Software\DSCBackup\Modules" -Destination "$env:ProgramFiles\WindowsPowerShell\" -Recurse -Force -Verbose:$VerboseState
        Copy-Item -Path "\\files\dfs\CISWindows\Software\DSCBackup\Modules" -Destination "${env:ProgramFiles(x86)}\WindowsPowerShell\" -Recurse -Force -Verbose:$VerboseState
    }

    if (-not $(Test-Path "$env:ProgramFiles\WindowsPowerShell\DscService")) {
        mkdir "$env:ProgramFiles\WindowsPowerShell\DscService"
    }
    Copy-Item -Path "$env:ProgramFiles\WindowsPowerShell\Modules" -Destination "$env:ProgramFiles\WindowsPowerShell\DscService" -Recurse -Force -Verbose:$VerboseState 
    New-DscChecksum "$env:ProgramFiles\WindowsPowerShell\DscService\Modules" -Force

    if (-not $(Test-Path "${env:ProgramFiles(x86)}\WindowsPowerShell\DscService")) {
        mkdir "${env:ProgramFiles(x86)}\WindowsPowerShell\DscService"
    }
    Copy-Item -Path "${env:ProgramFiles(x86)}\WindowsPowerShell\Modules" -Destination "${env:ProgramFiles(x86)}\WindowsPowerShell\DscService" -Recurse -Force -Verbose:$VerboseState
    New-DscChecksum "${env:ProgramFiles(x86)}\WindowsPowerShell\DscService\Modules" -Force

    if (-not $(Test-Path "$InstallDest\DSC")) {
        mkdir "$InstallDest\DSC"
    }
    Copy-Item -Path "\\files\dfs\CISWindows\Software\DSCBackup\Scripts\DSC" -Destination "$InstallDest" -Recurse -Force -Verbose:$VerboseState
    . $InstallDest\DSC\PullServerConfiguration.ps1
    PullServerConfiguration -ComputerName $ComputerName -PullPort $PullPort -CompliancePort $CompliancePort -OutputPath "$InstallDest\DSC\Config"

    Start-DscConfiguration -CimSession $ComputerName -Path "$InstallDest\DSC\Config" -Wait -Force -Verbose:$VerboseState
}

function Check-CisDscCompliance {
    param (
        [Parameter(Mandatory=$true)][string[]]$ComputerName,
        [boolean]$UseDefault = $true,
        [string]$MofFile = "$env:SystemDrive\DSC\Config",
        [string]$OutputPath = "$env:SystemDrive\DSC\Reports"
    )

    if (-not $(Test-Path $OutputPath)) {
        mkdir $OutputPath
    }

    if ($UseDefault) {
        $MofFile = "$env:SystemDrive\DSC\Config\localhost.mof"
        if (-not $(Test-Path $MofFile)) {
            Write-Warning "Template MOF not found! You should generate one first."
            $Credential = Get-Credential -Message "Please provide a valid credential to apply DSC settings. Make sure this credential has access to \\files.ad.brown.edu." -UserName "ad\adm_yqin"
            
            . $env:SystemDrive\DSC\Template.ps1
            # TODO: this should have been configured to encrypt user credential: https://blogs.msdn.microsoft.com/powershell/2014/01/31/want-to-secure-credentials-in-windows-powershell-desired-state-configuration/
            $cred = @{
                AllNodes = @(
                    @{
                        NodeName = $ComputerName
                        PsDscAllowDomainUser = $true
                        PsDscAllowPlainTextPassword = $true
                    }
                )
            }
            Template -ComputerName "localhost" -Credential $Credential -OutputPath "$env:SystemDrive\DSC\Config" -ConfigurationData $cred
        }
    }

    $oldpath = pwd
    cd $OutputPath
    Start-DSCEAscan -MofFile $MofFile -ComputerName $ComputerName -OutputPath $OutputPath
    Get-DSCEAreport -OutPath $OutputPath -Overall
    foreach ($comp in $ComputerName) {
        Get-DSCEAreport -OutPath $OutputPath -ComputerName $comp
    }
    .\OverallComplianceReport.html
    cd $oldpath
}
