<# Notes:

Authors: Jason Helmick and Melissa (Missy) Januszko

The bulk of this DC, DHCP, ADCS config is authored by Melissa (Missy) Januszko and Jason Helmick.
Currently on her public DSC hub located here: https://github.com/majst32/DSC_public.git

Additional contributors of note: Jeff Hicks

Disclaimer
This example code is provided without copyright and AS IS.  It is free for you to use and modify.

#>

@{
    AllNodes    = @(
        @{
            NodeName                    = '*'

            # Lab Password - assigned to Administrator and Users
            LabPassword                 = 'P@ssw0rd'

            # Common networking
            InterfaceAlias              = 'Ethernet'
            DefaultGateway              = '192.168.3.1'
            SubnetMask                  = 24
            AddressFamily               = 'IPv4'
            IPNetwork                   = '192.168.3.0/24'
            IPNatName                   = 'LabNat'
            DnsServerAddress            = '192.168.3.20'

            # Firewall settings to enable
            FirewallRuleNames           = @(
                'FPS-ICMP4-ERQ-In';
                'FPS-ICMP6-ERQ-In';
                'FPS-SMB-In-TCP'
            )

            # Domain and Domain Controller information
            DomainName                  = "production.com.au"
            DomainDN                    = "DC=PRODUCTION,DC=COM,DC=AU"
            DCDatabasePath              = "C:\NTDS"
            DCLogPath                   = "C:\NTDS"
            SysvolPath                  = "C:\Sysvol"
            PSDscAllowPlainTextPassword = $true
            PSDscAllowDomainUser        = $true
            DomainNameChild             = "actewagl.local"

            # DHCP Server Data
            DHCPName                    = 'LabNet'
            DHCPIPStartRange            = '192.168.4.200'
            DHCPIPEndRange              = '192.168.4.250'
            DHCPSubnetMask              = '255.255.255.0'
            DHCPState                   = 'Active'
            DHCPAddressFamily           = 'IPv4'
            DHCPLeaseDuration           = '00:00:05'
            DHCPScopeID                 = '192.168.4.0'
            DHCPDnsServerIPAddress      = '192.168.4.10'
            DHCPRouter                  = '192.168.3.1'

            # ADCS Certificate Services information
            CACN                        = 'production.com'
            CADNSuffix                  = "C=AU,L=Melbourne,S=Victoria,O=Transition"
            CADatabasePath              = "C:\windows\system32\CertLog"
            CALogPath                   = "C:\CA_Logs"
            ADCSCAType                  = 'EnterpriseRootCA'
            ADCSCryptoProviderName      = 'RSA#Microsoft Software Key Storage Provider'
            ADCSHashAlgorithmName       = 'SHA256'
            ADCSKeyLength               = 2048
            ADCSValidityPeriod          = 'Years'
            ADCSValidityPeriodUnits     = 2

            # Lability default node settings
            Lability_SwitchName         = 'LabNet'
            Lability_ProcessorCount     = 1
            Lability_MinimumMemory      = 1GB
            SecureBoot                  = $false
            Lability_Media              = '2016_x64_Standard_Core_EN_Eval'
            <#


Id                                      Arch Media Description
--                                      ---- ----- -----------
2019_x64_Standard_EN_Eval                x64   ISO Windows Server 2019 Standard 64bit English Evaluation with Desktop Experience
2019_x64_Standard_EN_Core_Eval           x64   ISO Windows Server 2019 Standard 64bit English Evaluation
2019_x64_Datacenter_EN_Eval              x64   ISO Windows Server 2019 Datacenter 64bit English Evaluation with Desktop Experience
2019_x64_Datacenter_EN_Core_Eval         x64   ISO Windows Server 2019 Datacenter Evaluation in Core mode
2016_x64_Standard_EN_Eval                x64   ISO Windows Server 2016 Standard 64bit English Evaluation
2016_x64_Standard_Core_EN_Eval           x64   ISO Windows Server 2016 Standard Core 64bit English Evaluation
2016_x64_Datacenter_EN_Eval              x64   ISO Windows Server 2016 Datacenter 64bit English Evaluation
2016_x64_Datacenter_Core_EN_Eval         x64   ISO Windows Server 2016 Datacenter Core 64bit English Evaluation
2016_x64_Standard_Nano_EN_Eval           x64   ISO Windows Server 2016 Standard Nano 64bit English Evaluation
2016_x64_Datacenter_Nano_EN_Eval         x64   ISO Windows Server 2016 Datacenter Nano 64bit English Evaluation
2012R2_x64_Standard_EN_Eval              x64   ISO Windows Server 2012 R2 Standard 64bit English Evaluation
2012R2_x64_Standard_EN_V5_Eval           x64   ISO Windows Server 2012 R2 Standard 64bit English Evaluation with WMF 5
2012R2_x64_Standard_EN_V5_1_Eval         x64   ISO Windows Server 2012 R2 Standard 64bit English Evaluation with WMF 5.1
2012R2_x64_Standard_Core_EN_Eval         x64   ISO Windows Server 2012 R2 Standard Core 64bit English Evaluation
2012R2_x64_Standard_Core_EN_V5_Eval      x64   ISO Windows Server 2012 R2 Standard Core 64bit English Evaluation with WMF 5
2012R2_x64_Standard_Core_EN_V5_1_Eval    x64   ISO Windows Server 2012 R2 Standard Core 64bit English Evaluation with WMF 5.1
2012R2_x64_Datacenter_EN_Eval            x64   ISO Windows Server 2012 R2 Datacenter 64bit English Evaluation
2012R2_x64_Datacenter_EN_V5_Eval         x64   ISO Windows Server 2012 R2 Datacenter 64bit English Evaluation with WMF 5
2012R2_x64_Datacenter_EN_V5_1_Eval       x64   ISO Windows Server 2012 R2 Datacenter 64bit English Evaluation with WMF 5.1
2012R2_x64_Datacenter_Core_EN_Eval       x64   ISO Windows Server 2012 R2 Datacenter Core 64bit English Evaluation
2012R2_x64_Datacenter_Core_EN_V5_Eval    x64   ISO Windows Server 2012 R2 Datacenter Core 64bit English Evaluation with WMF 5
2012R2_x64_Datacenter_Core_EN_V5_1_Eval  x64   ISO Windows Server 2012 R2 Datacenter Core 64bit English Evaluation with WMF 5.1
WIN81_x64_Enterprise_EN_Eval             x64   ISO Windows 8.1 64bit Enterprise English Evaluation
WIN81_x64_Enterprise_EN_V5_Eval          x64   ISO Windows 8.1 64bit Enterprise English Evaluation with WMF 5
WIN81_x64_Enterprise_EN_V5_1_Eval        x64   ISO Windows 8.1 64bit Enterprise English Evaluation with WMF 5.1
WIN81_x86_Enterprise_EN_Eval             x86   ISO Windows 8.1 32bit Enterprise English Evaluation
WIN81_x86_Enterprise_EN_V5_Eval          x86   ISO Windows 8.1 32bit Enterprise English Evaluation with WMF 5
WIN81_x86_Enterprise_EN_V5_1_Eval        x86   ISO Windows 8.1 32bit Enterprise English Evaluation with WMF 5.1
WIN10_x64_Enterprise_20H2_EN_Eval        x64   ISO Windows 10 64bit Enterprise 2009 English Evaluation (20H2)
WIN10_x86_Enterprise_20H2_EN_Eval        x86   ISO Windows 10 32bit Enterprise 2009 English Evaluation
WIN10_x64_Enterprise_LTSC_EN_Eval        x64   ISO Windows 10 64bit Enterprise LTSC 2019 English Evaluation
WIN10_x86_Enterprise_LTSC_EN_Eval        x86   ISO Windows 10 32bit Enterprise LTSC 2019 English Evaluation
  #>
        }

        <#    Available Roles for computers
        DC = Domain Controller
        DHCP = Dynamic Host Configuration Protocol
        ADCS = Active Directory Certificate SErvices - plus autoenrollment GPO's and DSC and web server certs
        Web = Basic web server
        RSAT = Remote Server Administration Tools for the client
        RDP = enables RDP and opens up required firewall rules
        DomainJoin = joions a computer to the domain
#>
        @{
            NodeName                = 'DC1PRODUCTION'
            IPAddress               = '192.168.3.20'
            Role                    = @('DC', 'ADCS','RDP')
            Lability_BootOrder      = 10
            Lability_BootDelay      = 600 # Number of seconds to delay before others
            Lability_timeZone       = 'US Mountain Standard Time' #[System.TimeZoneInfo]::GetSystemTimeZones()
            Lability_Media          = '2022_x64_Standard_EN_Eval'
            lability_startupmemory  = 4GB
            Lability_ProcessorCount = 3
            CustomBootStrap         = @'
                    # This must be set to handle larger .mof files
                    Set-Item -path wsman:\localhost\maxenvelopesize -value 1000
'@
        }

         @{
            NodeName               = 'DC1ACTEW'
            IPAddress              = '192.168.3.21'
            DnsServerAddress       = '192.168.3.20'
            #Role = 'DomainJoin' # example of multiple roles @('DomainJoin', 'Web')
            Role                   = @( 'Web','RSAT','RSAT-DHCP','DCCHILD')
            Lability_BootOrder     = 20
            lability_startupmemory = 4GB
            Lability_timeZone      = 'US Mountain Standard Time' #[System.TimeZoneInfo]::GetSystemTimeZones()
            Lability_Media         = '2019_x64_Standard_EN_CORE_Eval'
            Lability_ProcessorCount = 2
           <#  CustomBootStrap         = @'
                    # To enable PSRemoting on the client
                    Enable-PSRemoting -SkipNetworkProfileCheck -Force;
                    Set-Item -path wsman:\localhost\maxenvelopesize -value 1000 ;
                    Install-WindowsFeature -name AD-Domain-Services -IncludeManagementTools ;
                    Install-WindowsFeature -name RSAT-Role-Tools -IncludeManagementTools -IncludeAllSubFeature ;
                    ping dc1production.production.com.au | Out-file -append C:\test.log;
                    $User = "production\administrator" ;
                    $PWord = ConvertTo-SecureString -String "P@ssw0rd" -AsPlainText -Force ; 
                    $Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $User, $PWord ;
                    Import-Module ADDSDeployment ;
                    Install-ADDSDomain -SafeModeAdministratorPassword $Pword -Credential $Credential -NewDomainName "actewagl" -ParentDomainName "production.com.au" -InstallDNS -CreateDNSDelegation -DomainMode 7 -ReplicationSourceDC "DC1production.production.com.au"  -DatabasePath "C:\Windows\NTDS" -NewDomainNetbiosName "actew" -Confirm:$False -verbose | Out-file -append C:\test.log;
                    MD C:\temp ;
                    Invoke-webrequest -uri https://download.microsoft.com/download/B/0/0/B00291D0-5A83-4DE7-86F5-980BC00DE05A/AzureADConnect.msi -OutFile C:\temp\azureadconnect.msi -UseBasicParsing
'@ #>
        }

        @{
            NodeName               = 'DC1AWS'
            IPAddress              = '192.168.3.22'
            DnsServerAddress       = '192.168.3.20'
            #Role = 'DomainJoin' # example of multiple roles @('DomainJoin', 'Web')
            Role                   = @( 'Web','RSAT','RSAT-DHCP')
            Lability_BootOrder     = 20
            lability_startupmemory = 2GB
            Lability_timeZone      = 'US Mountain Standard Time' #[System.TimeZoneInfo]::GetSystemTimeZones()
            Lability_Media         = '2019_x64_Standard_EN_CORE_Eval'
            Lability_ProcessorCount = 2
            CustomBootStrap         = @'
                    # To enable PSRemoting on the client
                    Enable-PSRemoting -SkipNetworkProfileCheck -Force;
                    Set-Item -path wsman:\localhost\maxenvelopesize -value 1000 ;
                    Install-WindowsFeature -name AD-Domain-Services -IncludeManagementTools ;
                    Install-WindowsFeature -name RSAT-Role-Tools -IncludeManagementTools -IncludeAllSubFeature ;
                    ping dc1production.production.com.au | Out-file -append C:\test.log;
                    $User = "production\administrator" ;
                    $PWord = ConvertTo-SecureString -String "P@ssw0rd" -AsPlainText -Force ; 
                    $Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $User, $PWord ;
                    Import-Module ADDSDeployment ;
                    Install-ADDSDomain -SafeModeAdministratorPassword $Pword -Credential $Credential -NewDomainName "aws.iconwater.com.au" -ParentDomainName "production.com.au" -InstallDNS -CreateDNSDelegation -DomainMode 7 -ReplicationSourceDC "DC1production.production.com.au"  -DatabasePath "C:\Windows\NTDS" -NewDomainNetbiosName "aws" -Confirm:$False -verbose | Out-file -append C:\test.log;
                    MD C:\temp ;
                    Invoke-webrequest -uri https://download.microsoft.com/download/B/0/0/B00291D0-5A83-4DE7-86F5-980BC00DE05A/AzureADConnect.msi -OutFile C:\temp\azureadconnect.msi -UseBasicParsing
'@
        }

        @{
            NodeName               = 'DC2PROD'
            IPAddress              = '192.168.3.61'
            DnsServerAddress       = '192.168.3.20'
            #Role = 'DomainJoin' # example of multiple roles @('DomainJoin', 'Web')
            Role                   = @( 'Web','RSAT','RSAT-DHCP')
            Lability_BootOrder     = 20
            lability_startupmemory = 4GB
            Lability_timeZone      = 'US Mountain Standard Time' #[System.TimeZoneInfo]::GetSystemTimeZones()
            Lability_Media         = '2022_x64_Standard_EN_Eval'
            Lability_ProcessorCount = 2
            <# CustomBootStrap         = @'
                    # To enable PSRemoting on the client
                    Enable-PSRemoting -SkipNetworkProfileCheck -Force;
                    Install-WindowsFeature -name RSAT-Role-Tools -IncludeManagementTools -IncludeAllSubFeature ;
                    Install-WindowsFeature -name AD-Domain-Services -IncludeManagementTools ;
                    Import-Module ADDSDeployment ;
                    ping DC1PRODUCTION.production.com.au | Out-file -append C:\test.log
                    $User = "production\administrator" ;
                    $PWord = ConvertTo-SecureString -String "P@ssw0rd" -AsPlainText -Force ; 
                    $Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $User, $PWord ;
                    Install-ADDSDomainController `
                    -NoGlobalCatalog:$false `
                    -CreateDnsDelegation:$false `
                    -Credential $Credential `
                    -CriticalReplicationOnly:$false `
                    -DatabasePath "C:\Windows\NTDS" `
                    -DomainName "production.com.au" `
                    -InstallDns:$true `
                    -LogPath "C:\Windows\NTDS" `
                    -NoRebootOnCompletion:$false `
                    -ReplicationSourceDC "DC1PRODUCTION.production.com.au" `
                    -SiteName "Default-First-Site-Name" -SafeModeAdministratorPassword $PWord `
                    -SysvolPath "C:\Windows\SYSVOL" `
                    -Force:$true | Out-file -append C:\test.log;
                    MD C:\temp ;
                    Invoke-webrequest -uri https://download.microsoft.com/download/B/0/0/B00291D0-5A83-4DE7-86F5-980BC00DE05A/AzureADConnect.msi -OutFile C:\temp\azureadconnect.msi -UseBasicParsing
'@ #>
        }

        @{
            NodeName                = 'Cli1ACTEW'
            IPAddress               = '192.168.3.101'
            Role                    = @('RSAT', 'RDP')
            Lability_ProcessorCount = 2
            lability_startupmemory  = 4GB
            Lability_Media          = 'WIN10_x64_Enterprise_22H2_EN_Eval'
            Lability_BootOrder      = 20
            Lability_timeZone       = 'US Mountain Standard Time' #[System.TimeZoneInfo]::GetSystemTimeZones()
            Lability_Resource       = @(
                'Firefox'
            )
            CustomBootStrap         = @'
                    # To enable PSRemoting on the client
                    Enable-PSRemoting -SkipNetworkProfileCheck -Force;
'@
        }
        #>

    )
    NonNodeData = @{
        Lability = @{

            # You can uncomment this line to add a prefix to the virtual machine name.
            # It will not change the guest computername
            # See https://github.com/pluralsight/PS-AutoLab-Env/blob/master/Detailed-Setup-Instructions.md
            # for more information.

            #EnvironmentPrefix = 'AutoLab-'
            Media       = (
                @{
                    <#
                    ## This media is a replica of the default '2016_x64_Standard_Nano_EN_Eval' media
                    ## with the additional 'Microsoft-NanoServer-DSC-Package' package added.
                    Id              = '2016_x64_Standard_Nano_DSC_EN_Eval';
                    Filename        = '2016_x64_EN_Eval.iso';
                    Description     = 'Windows Server 2016 Standard Nano 64bit English Evaluation';
                    Architecture    = 'x64';
                    ImageName       = 'Windows Server 2016 SERVERSTANDARDNANO';
                    MediaType       = 'ISO';
                    OperatingSystem = 'Windows';
                    Uri             = 'http://download.microsoft.com/download/1/6/F/16FA20E6-4662-482A-920B-1A45CF5AAE3C/14393.0.160715-1616.RS1_RELEASE_SERVER_EVAL_X64FRE_EN-US.ISO';
                    Checksum        = '18A4F00A675B0338F3C7C93C4F131BEB';
                    CustomData      = @{
                        SetupComplete = 'CoreCLR';
                        PackagePath   = '\NanoServer\Packages';
                        PackageLocale = 'en-US';
                        WimPath       = '\NanoServer\NanoServer.wim';
                        Package       = @(
                            'Microsoft-NanoServer-Guest-Package',
                            'Microsoft-NanoServer-DSC-Package'
                            )
                        }
                    #>
                }
            ) # Custom media additions that are different than the supplied defaults (media.json)
            Network     = @( # Virtual switch in Hyper-V
                @{ Name = 'LabNet'; Type = 'Internal'; NetAdapterName = 'Ethernet'; AllowManagementOS = $true }
            )
            DSCResource = @(
                ## Download published version from the PowerShell Gallery or Github
                @{ Name = 'xActiveDirectory'; RequiredVersion = "3.0.0.0"; Provider = 'PSGallery' },
                @{ Name = 'xComputerManagement'; RequiredVersion = '4.1.0.0'; Provider = 'PSGallery' },
                @{ Name = 'xNetworking'; RequiredVersion = '5.7.0.0'; Provider = 'PSGallery' },
                @{ Name = 'xDhcpServer'; RequiredVersion = '3.0.0'; Provider = 'PSGallery' },
                @{ Name = 'xWindowsUpdate' ; RequiredVersion = '2.8.0.0'; Provider = 'PSGallery' },
                @{ Name = 'xPSDesiredStateConfiguration'; RequiredVersion = '9.1.0'; },
                @{ Name = 'xADCSDeployment'; RequiredVersion = '1.4.0.0'; Provider = 'PSGallery' },
                @{ Name = 'xDnsServer'; RequiredVersion = "1.16.0.0"; Provider = 'PSGallery' }

            )
            Resource    = @(
                @{
                    Id = 'Firefox'
                    Filename = 'Firefox-Latest.exe'
                    Uri = 'https://download.mozilla.org/?product=firefox-latest-ssl&os=win64&lang=en-US'
                

                }
            )
        }
    }
}
