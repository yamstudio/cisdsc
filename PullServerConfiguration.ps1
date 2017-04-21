Configuration PullServerConfiguration {

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
            Port = 8080
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
            Port = 8081
            CertificateThumbPrint = "AllowUnencryptedTraffic"
            PhysicalPath = "$env:SystemDrive\inetpub\wwwroot\PSDSCComplianceServer"
            State = "Started"
            UseSecurityBestPractices = $false
            DependsOn = ("[WindowsFeature]DSCServiceFeature", "[xDSCWebService]PSDSCPullServer")
        }
    }
}

$ComputerName = "TestServer-yqin"
Generate-TestServerConfiguration -OutputPath C:\DSC\Config
