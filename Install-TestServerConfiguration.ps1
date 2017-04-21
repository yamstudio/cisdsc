#Set-DscLocalConfigurationManager -ComputerName "TestServer-yqin" -Path "C:\DSC\Config" -Verbose
Start-DscConfiguration -ComputerName "TestServer-yqin" -Path "C:\DSC\Config" -Wait -Verbose -Force