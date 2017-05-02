Configuration PullServerConfiguration {
    
    param (
        [Parameter(Mandatory=$true)][string[]]$ComputerName,
        [int]$PullPort = 8080,
        [int]$CompliancePort = 8081
    )

    Import-DscResource -ModuleName PSDesiredStateConfiguration, xPSDesiredStateConfiguration

    Node $ComputerName {

        WindowsFeature IIS {
            Name = "Web-Server"
            Ensure = "Present"
        }
        
        WindowsFeature IISConsole {
            Name = "Web-Mgmt-Console"
            Ensure = "Present"
        }

        WindowsFeature DSCServiceFeature {
            Name = "DSC-Service"
            Ensure = "Present"
        }

        xDSCWebService PSDSCPullServer {
            EndPointName = "PSDSCPullServer"
            Ensure = "Present"
            Port = $PullPort
            CertificateThumbPrint = "AllowUnencryptedTraffic"
            PhysicalPath = "$env:SystemDrive\inetpub\wwwroot\PSDSCPullServer"
            ModulePath = "$env:ProgramFiles\WindowsPowershell\DscService\Modules"
            ConfigurationPath = "$env:ProgramFiles\WindowsPowershell\DscService\Configuration"
            State = "Started"
            UseSecurityBestPractices = $false
            DependsOn = "[WindowsFeature]DSCServiceFeature"
        }

        xDSCWebService PSDSCComplianceServer {
            EndPointName = "PSDSCComplianceServer"
            Ensure = "Present"
            Port = $CompliancePort
            CertificateThumbPrint = "AllowUnencryptedTraffic"
            PhysicalPath = "$env:SystemDrive\inetpub\wwwroot\PSDSCComplianceServer"
            State = "Started"
            UseSecurityBestPractices = $false
            DependsOn = ("[WindowsFeature]DSCServiceFeature", "[xDSCWebService]PSDSCPullServer")
        }
    }
}
