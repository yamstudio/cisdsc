[DSCLocalConfigurationManager()]
Configuration LCM_HttpPull {

    param (
        [Parameter(Mandatory=$true)][String[]]$ComputerName,
        [Parameter(Mandatory=$true)][String]$guid
    )

    Node $ComputerName {

        Settings {
            AllowModuleOverwrite = $true
            ConfigurationMode = 'ApplyAndAutoCorrect'
            RefreshMode = 'Pull'
            ConfigurationID = $guid
        }

        ConfigurationRepositoryWeb DSCHTTP {
            ServerURL = "http://DWIN2016DSCCIT.ad.brown.edu:8080/PSDSCPullServer.svc"
            AllowUnsecureConnection = $true
        }
    }
}

LCM_HttpPull -ComputerName DWIN2016DSCCIT -guid $([guid]::NewGuid()) -OutputPath "C:\DSC\Config"
