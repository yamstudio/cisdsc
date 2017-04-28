#Set-DscLocalConfigurationManager -ComputerName "TestServer-yqin" -Path "C:\DSC\Config" -Verbose

Set-DscLocalConfigurationManager -ComputerName DWIN2016DSCCIT -Path "C:\DSC\Config" -Verbose

$guid = $(Get-DscLocalConfigurationManager -CimSession DWIN2016DSCCIT | Select-Object -ExpandProperty ConfigurationID)
$source = "C:\DSC\Config\DWIN2016DSCCIT.mof"
$dest = "C:\Program Files (x86)\WindowsPowershell\DscService\Configuration\$guid.mof"
Copy-Item -Path $source -Destination $dest
New-DscChecksum $dest
Update-DscConfiguration -ComputerName DWIN2016DSCCIT -Wait -Verbose
