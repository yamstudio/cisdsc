[DSCLocalConfigurationManager()]
Configuration LCM_HttpPull {

    param (
        [Parameter(Mandatory=$true)][string[]]$ComputerName,
        [Parameter(Mandatory=$true)][string]$Guid,
        [Parameter(Mandatory=$true)][string]$PullServerName,
        [int]$Port = 8080
    )

    Node $ComputerName {

        Settings {
            AllowModuleOverwrite = $true
            ConfigurationMode = 'ApplyAndAutoCorrect'
            RefreshMode = 'Pull'
            ConfigurationID = $Guid
        }

        ConfigurationRepositoryWeb DSCHTTP {
            ServerURL = "http://$PullServerName.ad.brown.edu:$Port/PSDSCPullServer.svc"
            AllowUnsecureConnection = $true
        }
    }
}
