function Install-CisDscConfiguration {

    param(
        [Parameter(Mandatory=$true)][string[]]$ComputerName,
        [Parameter(Mandatory=$true)][string]$PullServerName,
        [int]$Port = 8080,
        [string]$InputDsc = "$env:SystemDrive:\DSC\Config",
        [switch]$Force
    )

    $VerboseState = $VerbosePreference -ne "SilentlyContinue"
    $ForceState = $Force.IsPresent
    $RestartArray = New-Object System.Collections.ArrayList
    $Guid = [guid]::NewGuid()

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
    . C:\DSC\LCM_HttpPull.ps1
    LCM_HttpPull -ComputerName $ComputerName -Guid $Guid -PullServerName $PullServerName -Port $Port -OutputPath "C:\DSC\Config"


    Set-DscLocalConfigurationManager -ComputerName $ComputerName -Path $InputDsc -Force:$ForceState -Verbose:$VerboseState

    return

    $Source = "C:\DSC\Config\$ComputerName.mof"
    $Dest = "C:\Program Files (x86)\WindowsPowershell\DscService\Configuration\$Guid.mof"
    Copy-Item -Path $Source -Destination $Dest
    New-DscChecksum $Dest
    Update-DscConfiguration -ComputerName $ComputerName -Wait -Verbose:$VerboseState
}

function Install-CisDscPullServer {
    param (
        [Parameter(Mandatory=$true)][string[]]$ComputerName,
        [int]$PullPort = 8080,
        [int]$CompliancePort = 8081
    )

    . C:\dsc\PullServerConfiguration.ps1
    PullServerConfiguration -ComputerName $ComputerName -PullPort $PullPort -CompliancePort $CompliancePort -OutputPath "C:\DSC\Config"
}

function Check-CisDscCompliance {
    param (
        [string[]]$ComputerName,
        [string]$MofFile,
        [string]$OutputPath
    )

}

Install-CisDscConfiguration -ComputerName "DWIN2016DSCCIT","DWIN2012DSCCIT" -PullServerName "DWIN2016DSCCIT" -Verbose -Force
