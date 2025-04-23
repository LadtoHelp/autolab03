<# Notes:

Authors: Jason Helmick and Melissa (Missy) Januszko

The bulk of this DC, DHCP, ADCS config is authored by Melissa (Missy) Januszko and Jason Helmick.
Currently on her public DSC hub located here: https://github.com/majst32/DSC_public.git

Additional contributors of note: Jeff Hicks

Disclaimer
This example code is provided without copyright and AS IS.  It is free for you to use and modify.

.notes
20250228 - Leroy - Added the Remote Event Log Management componenets to the firewall rules to allow Remote Event Log Management 

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
            DnsServerAddress            = '192.168.3.10'

            # Firewall settings to enable
            FirewallRuleNames           = @(
                'FPS-ICMP4-ERQ-In';
                'FPS-ICMP6-ERQ-In';
                'FPS-SMB-In-TCP';
                'RemoteEventLogSvc-In-TCP';
                'RemoteEventLogSvc-NP-In-TCP';
                'RemoteEventLogSvc-RPCSS-In-TCP'

            )

            # Domain and Domain Controller information
            DomainName                  = "padgettech.local"
            DomainDN                    = "DC=padgettech,DC=local"
            DCDatabasePath              = "C:\NTDS"
            DCLogPath                   = "C:\NTDS"
            SysvolPath                  = "C:\Sysvol"
            PSDscAllowPlainTextPassword = $true
            PSDscAllowDomainUser        = $true
            
            # vanitydomain
            Vanitydomain                = "starlighter.tech"

            # AD NETBIOSNAME
            DomainNetBIOSNAME           = "DEV"

            # DHCP Server Data
            DHCPName                    = 'LabNet'
            DHCPIPStartRange            = '192.168.3.200'
            DHCPIPEndRange              = '192.168.3.250'
            DHCPSubnetMask              = '255.255.255.0'
            DHCPState                   = 'Active'
            DHCPAddressFamily           = 'IPv4'
            DHCPLeaseDuration           = '00:08:00'
            DHCPScopeID                 = '192.168.3.0'
            DHCPDnsServerIPAddress      = '192.168.3.10'
            DHCPRouter                  = '192.168.3.1'

            # ADCS Certificate Services information
            CACN                        = 'Padgetech.local'
            CADNSuffix                  = "C=US,L=Phoenix,S=Arizona,O=RLS"
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
            SecureBoot                  = $true
            Lability_Media              = '2016_x64_Standard_Core_EN_Eval'

            #Additional Admin
            LabAdmin                    = 'LabAdmin'

            #RDS Details
            BUILDRDSINFRA = $true
            RDSCBName               = 'RDSConnectionBroker'
            RDSCollectionName      = @('RDSCollection01')
            RDSGatewayName         = 'Gateway'
            RDSWebAccessName       = 'RDWebAccess'
            RDSSessionHostName     = @('RDSessionHost')
            RDSLicenseMode      = 'PerUser'
            RDSGroups = @('RDS USERS')

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
            NodeName                = 'DC1'
            IPAddress               = '192.168.3.10'
            Role                    = @('DC', 'DHCP', 'ADCS')
            Lability_BootOrder      = 10
            Lability_BootDelay      = 60 # Number of seconds to delay before others
            Lability_timeZone       = 'US Mountain Standard Time' #[System.TimeZoneInfo]::GetSystemTimeZones()
            Lability_Media          = '2022_x64_Standard_EN_Core_Eval'
            Lability_MinimumMemory  = 2GB
            Lability_DvdDrive   = @{
                
                ## This will not create a IDE/SCSI controller. Therefore, you must enusre
                ## that the target controller already exists and does not already contain a disk
                ControllerNumber   = 0;
                ControllerLocation = 1;
                ## Lability can resolve the ISO path using the built-in environment variables
                ## NOTE: variable expansion is only available to Lability-specific node properties
                Path = "C:\Users\lelvi\Downloads\ExchangeServer2019-x64-CU14.ISO"
                VMGeneration = 2
               
            }
            Lability_ProcessorCount = 2
            CustomBootStrap         = @'
            # This must be set to handle larger .mof files
            Set-Item -path wsman:\localhost\maxenvelopesize -value 1000
'@
        } 
 
         @{
            NodeName                = 'S1'
            IPAddress               = '192.168.3.50'
            #Role = 'DomainJoin' # example of multiple roles @('DomainJoin', 'Web')
            Role                    = @('DomainJoin', 'Web', 'RDGateway','RSAT')
            Lability_MinimumMemory  = 6GB
            Lability_StartupMemory  = 6GB;
            Lability_ProcessorCount = 4
            Lability_BootOrder      = 20
            Lability_Resource       = @('SQL', 'MDT', 'ADKSETUP', 'ADKPESETUP', 'SQLSTUDIOMANAGMENT', 'CCMSETUPUPDATES', 'Microsoft SQL Server Reporting Services','Microsoft ODBC Driver 18 for SQL Server (x64)','Microsoft Entra Connect','Microsoft Edge')
            Lability_timeZone       = 'US Mountain Standard Time' #[System.TimeZoneInfo]::GetSystemTimeZones()
            Lability_Media          = '2022_x64_Standard_EN_Eval'
            Lability_DvdDrive       = @{
                
                ## This will not create a IDE/SCSI controller. Therefore, you must enusre
                ## that the target controller already exists and does not already contain a disk
                ControllerNumber   = 0;
                ControllerLocation = 1;
                ## Lability can resolve the ISO path using the built-in environment variables
                ## NOTE: variable expansion is only available to Lability-specific node properties
                Path               = "C:\Users\lelvi\Downloads\SQLServer2019-x64-ENU.iso"; 
            } 
            
        } 
        

         @{
            NodeName                = 'S2'
            IPAddress               = '192.168.3.51'
            Role                    = @('DomainJoin','RSAT', 'RDP','RDConnectionBroker','WEB')
            Lability_ProcessorCount = 2
            Lability_MinimumMemory  = 2GB
            #Lability_Media          = 'WIN10_x64_Enterprise_22H2_EN_Eval'
            Lability_Media          = '2022_x64_Standard_EN_Eval'
            Lability_BootOrder      = 20
            Lability_timeZone       = 'US Mountain Standard Time' #[System.TimeZoneInfo]::GetSystemTimeZones()
            Lability_Resource       = @()
            Lability_SecureBoot     = $true
            CustomBootStrap         = @'
                    # To enable PSRemoting on the client
                    Enable-PSRemoting -SkipNetworkProfileCheck -Force;
'@
        }

        @{
            NodeName                = 'S3'
            IPAddress               = '192.168.3.52'
            Role                    = @('DomainJoin','RSAT', 'RDP','RDSessionHost')
            Lability_ProcessorCount = 2
            Lability_MinimumMemory  = 2GB
            #Lability_Media          = 'WIN10_x64_Enterprise_22H2_EN_Eval'
            Lability_Media          = '2022_x64_Standard_EN_Eval'
            Lability_BootOrder      = 20
            Lability_timeZone       = 'US Mountain Standard Time' #[System.TimeZoneInfo]::GetSystemTimeZones()
            Lability_Resource       = @()
            Lability_SecureBoot     = $true
            CustomBootStrap         = @'
                    # To enable PSRemoting on the client
                    Enable-PSRemoting -SkipNetworkProfileCheck -Force;
'@
        } 
        

    )
    NonNodeData = @{
        Lability = @{

            # You can uncomment this line to add a prefix to the virtual machine name.
            # It will not change the guest computername
            # See https://github.com/pluralsight/PS-AutoLab-Env/blob/master/Detailed-Setup-Instructions.md
            # for more information.

            EnvironmentPrefix = 'DEV-'
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
                @{ Name = 'xPSDesiredStateConfiguration'; RequiredVersion = '9.1.0'; Provider = 'PSGallery' },
                #                @{ Name = 'PSDesiredStateConfiguration'; RequiredVersion = '1.1'; Provider = 'PSGallery' },
                @{ Name = 'xADCSDeployment'; RequiredVersion = '1.4.0.0'; Provider = 'PSGallery' },
                @{ Name = 'xDnsServer'; RequiredVersion = "1.16.0.0"; Provider = 'PSGallery' },
                @{ Name = 'ExchangeDsc'; RequiredVersion = "2.0.0"; Provider = 'PSGallery' },
                @{ Name = 'xPendingReboot'; RequiredVersion = "0.4.0.0" ; Provider = 'PSGallery' },
                @{ Name = 'ConfigMgrCBDsc'; RequiredVersion = "4.0.0"; Provider = 'PSGallery' },
                @{ Name = 'SqlServerDsc'; RequiredVersion = "15.2.0"; Provider = 'PSGallery' },
                @{ Name = 'UpdateServicesDsc'; RequiredVersion = "1.2.1"; Provider = 'PSGallery' },
                @{ Name = 'NetworkingDsc'; RequiredVersion = "8.2.0"; Provider = 'PSGallery' },
                @{ Name = 'xHyper-V' ; RequiredVersion = '3.15.0.0'; Provider = 'PSGallery' },
                @{ Name = 'xRemoteDesktopSessionHost' ; RequiredVersion = '2.1.0'; Provider = 'PSGallery' }

            )
            Resource    = @(
                @{
                    Id       = 'Firefox'
                    Filename = 'Firefox-Latest.exe'
                    Uri      = 'https://download.mozilla.org/?product=firefox-latest-ssl&os=win64&lang=en-US'

                },
                @{
                    Id       = 'UcmaRuntimeSetup'
                    Filename = "UcmaRuntimeSetup.exe"
                    Uri      = 'https://download.microsoft.com/download/2/C/4/2C47A5C1-A1F3-4843-B9FE-84C0032C61EC/UcmaRuntimeSetup.exe'

                },
                @{
                    Id       = 'ADConnect'
                    FileName = 'AzureADConnect.msi'
                    Uri      = 'https://download.microsoft.com/download/B/0/0/B00291D0-5A83-4DE7-86F5-980BC00DE05A/AzureADConnect.msi'
                },
                @{
                    Id       = 'Visual Studio 2013 x64'
                    FileName = 'vcredist_2013_x64.exe'
                    Uri      = 'https://download.visualstudio.microsoft.com/download/pr/10912041/cee5d6bca2ddbcd039da727bf4acb48a/vcredist_x64.exe'
                },
                @{
                    Id       = 'Visual Studio 2013 x86'
                    FileName = 'vcredist_2013_x86.exe'
                    Uri      = 'https://download.visualstudio.microsoft.com/download/pr/10912041/cee5d6bca2ddbcd039da727bf4acb48a/vcredist_x86.exe'
                },
                @{
                    Id       = "GoogleChrome"
                    FileName = "googlechromestandaloneenterprise64.msi"
                    Uri      = 'https://dl.google.com/tag/s/appguid%3D%7B8A69D345-D564-463C-AFF1-A69D9E530F96%7D%26iid%3D%7B671BD376-B7AB-C0FE-E1B6-A642ABF65A2B%7D%26lang%3Den%26browser%3D4%26usagestats%3D0%26appname%3DGoogle%2520Chrome%26needsadmin%3Dtrue%26ap%3Dx64-stable-statsdef_0%26brand%3DGCHC/dl/chrome/install/googlechromestandaloneenterprise64.msi'
                },
                @{
                    Id       = 'URLREWRITE'
                    FileName = 'rewrite_amd64_en-US.msi'
                    Uri      = 'https://download.microsoft.com/download/1/2/8/128E2E22-C1B9-44A4-BE2A-5859ED1D4592/rewrite_amd64_en-US.msi'
                },
                @{
                    Id              = 'SQL'
                    DestinationPath = '\Resources\SQL'
                    FileName        = 'SQLEXPR_x64_ENU.exe'
                    Checksum        = ''
                },
                @{
                    Id       = "MDT"
                    FileName = "MicrosoftDeploymentToolkit_x64.msi"
                    Checksum = ''
                    Uri      = 'https://download.microsoft.com/download/3/3/9/339BE62D-B4B8-4956-B58D-73C4685FC492/MicrosoftDeploymentToolkit_x64.msi'
                },
                @{
                    Id       = "ADKSETUP"
                    FileName = "ADK.zip"
                    Checksum = ''
                    Expand   = $true
                },
                @{
                    ID       = "ADKPESETUP"
                    FileName = "ADKWinPEAddons.zip"
                    Checksum = ''
                    Expand   = $true
                },
                @{
                    ID       = "SQLSTUDIOMANAGMENT"
                    FileName = "SSMS-Setup-ENU.exe"
                    URI      = "https://download.microsoft.com/download/b/9/7/b97061b9-9b9c-4bc7-86de-22b262c016d1/SSMS-Setup-ENU.exe"
                    Checksum = ''
                },
                @{
                    ID              = "CCMSETUPUPDATES"
                    FileName        = "CCMUPDATES2403.zip"
                    Checksum        = ''
                    Expand          = $true
                },
                @{
                    ID              = "CCMSETUPUPDATES2409"
                    FileName        = "CCMUPDATES2409.zip"
                    Checksum        = ''
                    Expand          = $true
                },
                @{
                    ID              = "Microsoft SQL Server Reporting Services"
                    FileName        = "SQLServerReportingServices.exe"
                    Checksum        = ''
                },
                @{
                    ID              =  'Microsoft ODBC Driver 18 for SQL Server (x64)'
                    DestinationPath = '\Resources\SQL'
                    FileName        = "msodbcsql_18_x64.msi"
                    Checksum        = ''
                    URI             = "https://download.microsoft.com/download/4/f/e/4fed6f4b-dc42-4255-b4b4-70f8e2a35a63/en-US/18.3.3.1/x64/msodbcsql.msi"
                    


                },
                @{
                    ID              = 'Microsoft Entra Connect'
                    DestinationPath = '\Resources\EntraConnect'
                    Filename        = "AzureADConnect.msi"
                    URI             = 'https://download.microsoft.com/download/B/0/0/B00291D0-5A83-4DE7-86F5-980BC00DE05A/AzureADConnect.msi'
                    Checksum        = ''
                },
                @{
                    ID              = 'Microsoft Edge'
                    DestinationPath = '\Resources\Edge'
                    FileName        = 'MicrosoftEdgeEnterpriseX64.msi'
                    URI             = 'https://go.microsoft.com/fwlink/?LinkID=2093437'
                },
                @{
                    ID              = '.NET Framework 4.8'
                    DestinationPath = '\Resources\.NET Framework 4.8'
                    FileName        = '\.NET Framework 4.8\NDP48-x86-x64-AllOS-ENU.exe'
                    Checksum        = ''
                }
            )
        }
    }
}
