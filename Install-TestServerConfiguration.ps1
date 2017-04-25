#Set-DscLocalConfigurationManager -ComputerName "TestServer-yqin" -Path "C:\DSC\Config" -Verbose
Start-DscConfiguration -ComputerName "DWIN2016DSCCIT" -Path "C:\DSC\Config" -Wait -Verbose -Force