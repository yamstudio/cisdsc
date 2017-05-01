function Install-CisDsc{

    param(
        [Parameter(Mandatory=$true)][string[]]$ComputerName,
        [string]$InputDsc = "$env:SystemDrive:\DSC\Config",
        [boolean]$Force = $false
    )

    try {
        foreach ($comp in $ComputerName) {
            if ($(Invoke-Command -ComputerName $comp {Get-WmiObject -class win32_operatingsystem | % caption}) -notlike "Microsoft Windows Server 201*") {
                Write-Warning "Machine $comp does not have a supported OS version."
                continue
            }
            if ($(Invoke-Command -ComputerName $comp {$PSVersionTable.PSVersion | % Major}) -lt 5) {
                
            }
        }
    } catch {
        Write-Warning "CRITICAL: Failed to check target WMF version - please check network and permission!"
        return
    }

    Set-DscLocalConfigurationManager -ComputerName $ComputerName -Path $InputDsc -Force $false -Verbose

    $guid = $(Get-DscLocalConfigurationManager -CimSession $ComputerName | % ConfigurationID)
    $source = "C:\DSC\Config\$ComputerName.mof"
    $dest = "C:\Program Files (x86)\WindowsPowershell\DscService\Configuration\$guid.mof"
    Copy-Item -Path $source -Destination $dest
    New-DscChecksum $dest
    Update-DscConfiguration -ComputerName $ComputerName -Wait -Verbose
}

Install-CisDsc -ComputerName LOCALHOST