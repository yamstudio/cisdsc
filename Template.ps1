﻿Configuration Template {

    param(
        [Parameter(Mandatory=$true)][string[]]$ComputerName,
        [Parameter(Mandatory)][PSCredential]$Credential,
        [boolean]$SkipBrownNetworkSettings = $false
    )

    Import-DscResource -ModuleName PSDesiredStateConfiguration, xSystemSecurity, xRemoteDesktopAdmin

    Node $ComputerName {


        # CREATE ADMIN DIRECTORY
        # create C:\AdminFiles
        File AdminFiles {
            DestinationPath = "$env:SystemDrive\AdminFiles"
            Ensure = "Present"
            Type = "Directory"
        }


        # NETWORK CONFIGURATION
        # ensure network interface BrownNetwork is present - prerequisite for DNSServer, WINSServer, DeviceManagerReceiveSideScaling
        Script BrownNetwork {
            GetScript = {
                return @{
                    Result = [string]$(Get-WmiObject Win32_NetworkAdapter | Where-Object Name -like "*Ethernet Adapter*" | % NetConnectionID)
                }
            }
            TestScript = {
                if ($(Get-WmiObject Win32_NetworkAdapter | % NetConnectionID).Contains("BrownNetwork")) {
                    Write-Verbose "BrownNetwork found!"
                    return $true
                } else {
                    Write-Verbose "BrownNetwork not found!"
                    $SkipBrownNetworkSettings = $true
                    return $false
                }
            }
            SetScript = {
                $adapter = $(Get-WmiObject Win32_NetworkAdapter | Where-Object Name -like "*Ethernet Adapter*")
                if (($adapter -eq $null) -or ($adapter[1] -ne $null)) {
                    Write-Warning "CRITICAL: Something is wrong with network adapters - not sure if we should proceed."                 
                } else {
                    $adapter.NetConnectionID = "BrownNetwork"
                    $adapter.Put()
                    $SkipBrownNetworkSettings = $false
                }
            }
        }

        # set DNS addresses to two of 10.4.21.{2, 3, 4, 5}, and 10.1.1.10
        Script DNSServer {
            DependsOn = "[Script]BrownNetwork"
            GetScript = {
                if ($SkipBrownNetworkSettings) {
                    return @{
                        Result = $null
                    }
                }
                return @{
                    Result = $(Get-DnsClientServerAddress -InterfaceAlias "BrownNetwork" -AddressFamily IPv4 | Select-Object -ExpandProperty ServerAddresses)
                }
            }
            TestScript = {
                if ($SkipBrownNetworkSettings) {
                    Write-Warning "CRITICAL: BrownNetwork not found - cowardly skipping configuration."
                    return $true
                }
                $dns = $(Get-DnsClientServerAddress -InterfaceAlias "BrownNetwork" -AddressFamily IPv4 | Select-Object -ExpandProperty ServerAddresses)
                if ($dns[0] -match "^10.4.21.[2-5]") {
                    if ($dns[1] -match "^10.4.21.[2-5]") {
                        if ($dns[2] -eq "10.1.1.10") {
                            Write-Verbose "DNS Server is compliant."
                            return $true
                        }
                    }
                }
                Write-Verbose "DNS Server is not compliant."
                return $false
            }
            SetScript = {
                Write-Verbose "Setting correct DNS Server addresses."
                $dns1 = Get-Random -Minimum 2 -Maximum 6
                do { 
                    $dns2 = Get-Random -Minimum 2 -Maximum 6 
                } while ($dns1 -eq $dns2) 
                $dns1 = "10.4.21." + [string]$dns1
                $dns2 = "10.4.21." + [string]$dns2
                Set-DnsClientServerAddress -InterfaceAlias "BrownNetwork" -Addresses $dns1, $dns2, "10.1.1.10"
            }
        }
        
        # set DNS suffixes
        # manipulate registry key directly for simplicity
        Registry DNSSuffix {
            Key = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
            Ensure = "Present"
            ValueName = "SearchList"
            ValueData = "ad.brown.edu,brown.edu,qad.brown.edu,services.brown.edu"
            ValueType = "String"
        }

        # set WINS address
        Script WINSServer {
            DependsOn = "[Script]BrownNetwork"
            GetScript = {
                if ($SkipBrownNetworkSettings) {
                    return @{
                        Result = $null
                    }
                }
                return @{
                    Result = [string]$(netsh interface ipv4 show winsserver)
                }
            }
            TestScript = {
                if ($SkipBrownNetworkSettings) {
                    Write-Warning "CRITICAL: BrownNetwork not found - cowardly skipping configuration."
                    return $true
                }
                $state = [string]$(netsh interface ipv4 show winsserver) -replace '\s', ''
                if ($state -like "*BrownNetwork?StaticallyConfiguredWINSServers:10.4.21.5*") {
                    Write-Verbose "WINS Server is compliant."
                    return $true
                } else {
                    Write-Verbose "WINS Server is not compliant."
                    return $false
                }
            }
            SetScript = {
                Write-Verbose "Setting WINS Server to 10.4.21.5."
                netsh interface ipv4 delete winsserver name=BrownNetwork address=all
                netsh interface ipv4 add winsserver name=BrownNetwork address=10.4.21.5 index=0
            }
        }


        # disable LMHOSTS lookup
        Script LMHOSTS {
            GetScript = {
                try {
                    return @{
                        Result = [string]$(Get-ItemPropertyValue "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" "EnableLMHOSTS")
                    }
                } catch {
                    return @{
                        Result = "-1"
                    }
                }
            }
            TestScript = {
                try {
                    if ([int]$(Get-ItemPropertyValue "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" "EnableLMHOSTS") -eq 0) {
                        Write-Verbose "LMHOSTS Lookup is compliant: expected `"disabled`", found `"disabled`"."
                        return $true
                    } else {
                        Write-Verbose "LMHOSTS Lookup is not compliant: expected `"disabled`", found `"enabled`"."
                    }
                } catch {
                    Write-Verbose "LMHOSTS Lookup key is not found."
                }
                return $false
            }
            SetScript = {
                Write-Verbose "Disabling LMHOSTS Lookup."
                $conf = [WmiClass]'Win32_NetworkAdapterConfiguration'
                $conf.EnableWins($false, $false)
            }
        }

        # disable IPv6
        Registry IPv6 {
            Key = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"
            Ensure = "Present"
            Hex = $true
            ValueName = "DisabledComponents"
            ValueData = "0xffffffff"
            ValueType = "Dword"
        }


        # SERVICES
        # TODO: disable Distributed Link Tracking Server
        # inapplicable to Server 2012/2016

        # set Print Spooler to Manual
        Service PrintSpooler {
            Name = "Spooler"
            State = "Stopped"
            StartupType = "Manual"
        }

        
        # INTERNET EXPLORER
        # disable Enhanced Security Configuration for admin
        # manipulate registry key directly, couldn't find better way
        Registry AdminESC {
            Key = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}"
            Ensure = "Present"
            ValueName = "IsInstalled"
            ValueData = "0"
            ValueType = "Dword"
        }

        # enable Enhanced Security Configuration for user
        # manipulate registry key directly, couldn't find better way
        Registry UserESC {
            Key = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}"
            Ensure = "Present"
            ValueName = "IsInstalled"
            ValueData = "1"
            ValueType = "Dword"
        }


        # USER ACCOUNT CONTROL
        # disable User Account Control
        xUAC UAC {
            Setting = "NeverNotify"
        }


        # PERFORMANCE OPTIONS
        # set Data Execution Prevention
        # TODO: this script does not seem to work on Server 2012 machines
        Script DEP {
            GetScript = {
                return @{
                    Result = [string]$(Get-WmiObject Win32_OperatingSystem | Select-Object -ExpandProperty DataExecutionPrevention_SupportPolicy)
                }
            }
            TestScript = {
                $state = [int]$(Get-WmiObject Win32_OperatingSystem | Select-Object -ExpandProperty DataExecutionPrevention_SupportPolicy)
                if ($state -eq 2) {
                    Write-Verbose "Data Execution Prevention is compliant: expected 2, found 2."
                    return $true
                } else {
                    Write-Verbose "Data Execution Prevention is not compliant: expected 2, found $state."
                    return $false
                }
            }
            SetScript = {
                Write-Verbose "Setting Data Execution Prevention Support Policy to 2."
                $OSObj = $(Get-WmiObject Win32_OperatingSystem)
                $OSObj.DataExecutionPrevention_SupportPolicy = 2
                $OSObj.Put()
            }
        }
        
        # turn on Adjust for Best Performance
        # manipulate registry key directly, couldn't find better way
        Registry AdjustForBestPerformance {
            Key = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects"
            Ensure = "Present"
            Hex = $true
            ValueName = "VisualFXSetting"
            ValueData = "0x2"
            ValueType = "Dword"
        }


        # TERMINAL SERVICES CONFIGURATION
        # enable remote access
        xRemoteDesktopAdmin RemoteDesktop {
            Ensure = "Present"
            UserAuthentication = "Secure"
        }


        # SERVER MANAGER
        # disable Server Manager from startup
        Registry ServerManager {
            Key = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\ServerManager"
            Ensure = "Present"
            ValueName = "DoNotOpenServerManagerAtLogon"
            ValueData = "1"
            ValueTYPE = "Dword"
        }
        
        # remove Server Manager from Task Scheduler
        Script ServerManagerTask {
            GetScript = {
                return @{
                    Result = $([string]$(Get-ScheduledTask -TaskName ServerManager | Select-Object -ExpandProperty State)).ToLower()
                }
            }
            TestScript = {
                $state = $([string]$(Get-ScheduledTask -TaskName ServerManager | Select-Object -ExpandProperty State)).ToLower()
                if ($state -eq "disabled") {
                    Write-Verbose "Scheduled task for Server Manager is compliant: expected `"disabled`", found `"disabled`"."
                    return $true
                } else {
                    Write-Verbose "Scheduled task for Server Manager is not compliant: expected `"disabled`", found `"$state`"."
                    return $false
                }
            }
            SetScript = {
                Write-Verbose "Disabling scheduled task for Server Manager."
                Disable-ScheduledTask -TaskPath "\Microsoft\Windows\Server Manager\" -TaskName ServerManager
            }
        }


        # BGINFO
        # download BGInfo
        # TODO: fix credential issue
        File BGInfo {
            DestinationPath = "$env:SystemDrive\AdminFiles\BGInfo32-64"
            Ensure = "Present"
            #SourcePath = "\\files\dfs\CISWindows\Software\DSCBackup\BGInfo32-64"
            Type = "Directory"
            Checksum = "SHA-256"
            Force = $true
            #MatchSource = $true
            #Recurse = $true
            #Credential = $Credential
        }
    
        # set BGInfo registry key
        Registry BGInfoKey {
            DependsOn = "[File]BGInfo"
            Ensure = "Present"
            Key = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
            ValueName = "BGInfo"
            ValueData = "C:\AdminFiles\BgInfo32-64\bginfo64.exe C:\AdminFiles\BgInfo32-64\config2.bgi /NOLICPROMPT /timer:0"
            ValueType = "String"
        }


        # SMB
        # disable smb1 from windows features
        WindowsFeature SMB1 {
            Name = "FS-SMB1"
            Ensure = "Absent"
        }


        # PATCH KB3125869
        # add key manually, for more info: https://technet.microsoft.com/en-us/library/security/ms15-124.aspx
        Registry KB3125869_Key1 {
            Key = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ALLOW_USER32_EXCEPTION_HANDLER_HARDENING"
            ValueName = "iexplore.exe"
            ValueData = "1"
            ValueType = "Dword"
        }

        # add key manually, for more info: https://technet.microsoft.com/en-us/library/security/ms15-124.aspx
        Registry KB3125869_Key2 {
            Key = "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ALLOW_USER32_EXCEPTION_HANDLER_HARDENING"
            ValueName = "iexplore.exe"
            ValueData = "1"
            ValueType = "Dword"
        }


        # RECEIVE-SIDE SCALING
        # enable receive-side scaling in netsh
        Script NetshReceiveSideScaling {
            GetScript = {
                return @{
                    Result = [string]$(netsh interface tcp show global)
                }
            }
            TestScript = {
                $state = [string]$(netsh interface tcp show global) -replace '\s', ''
                if ($state -like "*Receive-SideScalingState:enabled*") {
                    Write-Verbose "Receive-Side Scaling in netsh is compliant: expected `"enabled`", found `"enabled`"."
                    return $true
                } else {
                    Write-Verbose "Receive-Side Scaling in netsh is not compliant: expected `"enabled`", found `"disabled`"."
                    return $false
                }
            }
            SetScript = {
                Write-Verbose "Enabling Received-Side Scaling in netsh."
                netsh interface tcp set global rss=enabled
            }
        }

        # disable receive-side scaling in Device Manager
        Script DeviceManagerReceiveSideScaling {
            DependsOn = "[Script]BrownNetwork"
            GetScript = {
                if ($SkipBrownNetworkSettings) {
                    return @{
                        Result = $null
                    }
                }
                return @{
                    Result = [string]$(Get-NetAdapterRss -Name "BrownNetwork" | Select-Object -ExpandProperty Enabled)
                }
            }
            TestScript = {
                if ($SkipBrownNetworkSettings) {
                    Write-Warning "CRITICAL: BrownNetwork not found - cowardly skipping configuration."
                    return $true
                }
                if (Get-NetAdapterRss -Name "BrownNetwork" | Select-Object -ExpandProperty Enabled) {
                    Write-Verbose "Receive-Side Scaling in Device Manager is not compliant: expected `"disabled`", found `"enabled`"."
                    return $false
                } else {
                    Write-Verbose "Receive-Side Scaling in Device Manager is compliant: expected `"disabled`", found `"disabled`"."
                    return $true
                }
            }
            SetScript = {
                Write-Verbose "Disabling Receive-Side Scaling in Device Manager."
                Disable-NetAdapterRss -Name "BrownNetwork"
            }
        }
    }   
}
