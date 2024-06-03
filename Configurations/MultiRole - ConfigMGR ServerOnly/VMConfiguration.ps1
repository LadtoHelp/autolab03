

Configuration AutoLab {

$LabData = Import-PowerShellDataFile -Path $PSScriptRoot\*.psd1
$Secure = ConvertTo-SecureString -String "$($labdata.allnodes.labpassword)" -AsPlainText -Force
$credential = New-Object -typename Pscredential -ArgumentList Administrator, $secure

#region DSC Resources
    Import-DSCresource -ModuleName "PSDesiredStateConfiguration" -ModuleVersion "1.1"
    Import-DSCResource -modulename "xPSDesiredStateConfiguration" -ModuleVersion  "9.1.0"
    Import-DSCResource -modulename "xActiveDirectory" -ModuleVersion  "3.0.0.0"
    Import-DSCResource -modulename "xComputerManagement" -ModuleVersion  "4.1.0.0"
    Import-DSCResource -modulename "xNetworking" -ModuleVersion  "5.7.0.0"
    Import-DSCResource -modulename "xDhcpServer" -ModuleVersion  "3.0.0"
    Import-DSCResource -modulename 'xWindowsUpdate' -ModuleVersion  '2.8.0.0'
    Import-DSCResource -modulename 'xADCSDeployment' -ModuleVersion  '1.4.0.0'
    Import-DSCResource -modulename 'xDnsServer' -ModuleVersion  '1.16.0.0'
    Import-DscResource -ModuleName 'ExchangeDsc'
    Import-DscResource -ModuleName 'xPendingReboot' -ModuleVersion "0.4.0.0"
    Import-DscResource -ModuleName ConfigMgrCBDsc -ModuleVersion  '3.0.0'
    Import-DscResource -ModuleName SqlServerDsc -ModuleVersion 15.2.0
    Import-DscResource -ModuleName UpdateServicesDsc -ModuleVersion 1.2.1
    Import-DscResource -ModuleName NetworkingDsc -ModuleVersion 8.2.0
    Import-DscResource -ModuleName xHyper-V -ModuleVersion 3.15.0.0


#endregion
#region All Nodes
    node $AllNodes.Where({$true}).NodeName {
#endregion
#region LCM configuration

        LocalConfigurationManager {
            RebootNodeIfNeeded   = $true
            AllowModuleOverwrite = $true
            ConfigurationMode = 'ApplyAndMonitor'
            ActionAfterReboot = 'ContinueConfiguration'
            ConfigurationModeFrequencyMins = 15
        }

#endregion

#region TLS Settings in registry

registry TLS {
    Ensure = "present"
    Key =  'HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NetFramework\v4.0.30319'
    ValueName = 'SchUseStrongCrypto'
    ValueData = '1'
    ValueType = 'DWord'
}

#endregion

registry Edge_FirstRun {
    Key = "HKLM:\Software\Policies\Microsoft\Edge"
    ValueName = 'HideFirstRunExperience'
    ValueData = 1
    ValueType = 'DWord'
}

#region IPaddress settings

    If (-not [System.String]::IsNullOrEmpty($node.IPAddress)) {
        xIPAddress 'PrimaryIPAddress' {
            IPAddress      = $node.IPAddress
            InterfaceAlias = $node.InterfaceAlias
            AddressFamily  = $node.AddressFamily
        }

        If (-not [System.String]::IsNullOrEmpty($node.DefaultGateway)) {
            xDefaultGatewayAddress 'PrimaryDefaultGateway' {
                InterfaceAlias = $node.InterfaceAlias
                Address = $node.DefaultGateway
                AddressFamily = $node.AddressFamily
            }
        }

        If (-not [System.String]::IsNullOrEmpty($node.DnsServerAddress)) {
            xDnsServerAddress 'PrimaryDNSClient' {
                Address        = $node.DnsServerAddress
                InterfaceAlias = $node.InterfaceAlias
                AddressFamily  = $node.AddressFamily
            }
        }

        If (-not [System.String]::IsNullOrEmpty($node.DnsConnectionSuffix)) {
            xDnsConnectionSuffix 'PrimaryConnectionSuffix' {
                InterfaceAlias = $node.InterfaceAlias
                ConnectionSpecificSuffix = $node.DnsConnectionSuffix
            }
        }
    } #End IF

#endregion

#region Firewall Rules

$LabData = Import-PowerShellDataFile -Path $psscriptroot\*.psd1
    $FireWallRules = $labdata.Allnodes.FirewallRuleNames

        foreach ($Rule in $FireWallRules) {
        xFirewall $Rule {
            Name = $Rule
            Enabled = 'True'
        }
} #End foreach

    } #end Firewall Rules
#endregion

#region Domain Controller config

    node $AllNodes.Where({$_.Role -eq 'DC'}).NodeName {

    $DomainCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ("$($node.DomainName)\$($Credential.UserName)", $Credential.Password)

        xComputer ComputerName {
            Name = $Node.NodeName
        }

        ## Hack to fix DependsOn with hypens "bug" :(
        foreach ($feature in @(
                'DNS',
                'AD-Domain-Services',
                'RSAT-AD-Tools',
                'RSAT-AD-PowerShell',
                'GPMC'
                #For Gui, might like
                #'RSAT-DNS-Server',
                #'RSAT-AD-AdminCenter',
                #'RSAT-ADDS-Tools'

            )) {
            WindowsFeature $feature.Replace('-','') {
                Ensure = 'Present';
                Name = $feature;
                IncludeAllSubFeature = $False;
            }
        } #End foreach

            xADDomain FirstDC {
                DomainName = $Node.DomainName
                DomainAdministratorCredential = $Credential
                SafemodeAdministratorPassword = $Credential
                DatabasePath = $Node.DCDatabasePath
                LogPath = $Node.DCLogPath
                SysvolPath = $Node.SysvolPath
                DependsOn = '[WindowsFeature]ADDomainServices'
            }

            xADForestProperties FirstDC {
                ForestName                   = $Node.DomainName
                UserPrincipalNameSuffixToAdd = "$($node.vanitydomain)"
            }

        #Add OU, Groups, and Users
    $OUs = (Get-Content $PSScriptRoot\AD-OU.json | ConvertFrom-Json)
    $Users = (Get-Content $PSScriptRoot\AD-Users.json | ConvertFrom-Json)
    $Groups = (Get-Content $PSScriptRoot\AD-Group.json | ConvertFrom-Json)

        foreach ($OU in $OUs) {
            xADOrganizationalUnit $OU.Name {
            Path = $node.DomainDN
            Name = $OU.Name
            Description = $OU.Description
            ProtectedFromAccidentalDeletion = $False
            Ensure = "Present"
            DependsOn = '[xADDomain]FirstDC'
        }
        } #OU

        foreach ($user in $Users) {

            xADUser $user.samaccountname {
                Ensure = "Present"
                Path = $user.distinguishedname.split(",",2)[1]
                DomainName = $node.domainname
                Username = $user.samaccountname
                GivenName = $user.givenname
                Surname = $user.Surname
                DisplayName = $user.Displayname
                Description = $user.description
                Department = $User.department
                Enabled = $true
                Password = $DomainCredential
                DomainAdministratorCredential = $DomainCredential
                PasswordNeverExpires = $True
                DependsOn = '[xADDomain]FirstDC'
                PasswordAuthentication = 'Negotiate'
            }
        } #user

        Foreach ($group in $Groups) {
            xADGroup $group.Name {
                GroupName = $group.name
                Ensure = 'Present'
                Path = $group.distinguishedname.split(",",2)[1]
                Category = $group.GroupCategory
                GroupScope = $group.GroupScope
                Members = $group.members
                DependsOn = '[xADDomain]FirstDC'
            }
        }

    #prestage Web Server Computer objects

        [string[]]$WebServers = $Null

        foreach ($N in $AllNodes) {
            if ($N.Role -eq "Web") {

                $WebServers = $WebServers + "$($N.NodeName)$"

                xADComputer "CompObj_$($N.NodeName)" {
                    ComputerName = "$($N.NodeName)"
                    DependsOn = '[xADOrganizationalUnit]Servers'
                    DisplayName = $N.NodeName
                    Path = "OU=Servers,$($N.DomainDN)"
                    Enabled = $True
                    DomainAdministratorCredential = $DomainCredential
                    }
                }
            }

     #add Web Servers group with Web Server computer objects as members

            xADGroup WebServerGroup {
                GroupName = 'Web Servers'
                GroupScope = 'Global'
                DependsOn = '[xADOrganizationalUnit]IT'
                Members = $WebServers
                Credential = $DomainCredential
                Category = 'Security'
                Path = "OU=IT,$($Node.DomainDN)"
                Ensure = 'Present'
                }

    } #end nodes DC

#endregion

#region DHCP
    node $AllNodes.Where({$_.Role -eq 'DHCP'}).NodeName {

        foreach ($feature in @(
                'DHCP'
                #'RSAT-DHCP'
            )) {

            WindowsFeature $feature.Replace('-','') {
                Ensure = 'Present';
                Name = $feature;
                IncludeAllSubFeature = $False;
                DependsOn = '[xADDomain]FirstDC'
            }
        } #End foreach

        xDhcpServerAuthorization 'DhcpServerAuthorization' {
            Ensure = 'Present'
            IsSingleInstance = 'yes'
            DependsOn = '[WindowsFeature]DHCP'
        }

        xDhcpServerScope 'DhcpScope' {
            Name = $Node.DHCPName
            ScopeID = $node.DHCPScopeID
            IPStartRange = $Node.DHCPIPStartRange
            IPEndRange = $Node.DHCPIPEndRange
            SubnetMask = $Node.DHCPSubnetMask
            LeaseDuration = $Node.DHCPLeaseDuration
            State = $Node.DHCPState
            AddressFamily = $Node.DHCPAddressFamily
            DependsOn = '[WindowsFeature]DHCP'
        }

        <# Deprecated
        xDhcpServerOption 'DhcpOption' {
            ScopeID = $Node.DHCPScopeID
            DnsServerIPAddress = $Node.DHCPDnsServerIPAddress
            Router = $node.DHCPRouter
            AddressFamily = $Node.DHCPAddressFamily
            DependsOn = '[xDhcpServerScope]DhcpScope'
        }
        #>

    } #end DHCP Config
 #endregion

#region Web config
   node $AllNodes.Where({$_.Role -eq 'Web'}).NodeName {

        foreach ($feature in @(
                'web-Server'

            )) {
            WindowsFeature $feature.Replace('-','') {
                Ensure = 'Present'
                Name = $feature
                IncludeAllSubFeature = $False
            }
        }

    }#end Web Config
#endregion

#region DomainJoin config
   node $AllNodes.Where({$_.Role -eq 'DomainJoin'}).NodeName {

    $DomainCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ("$($node.DomainName)\$($Credential.UserName)", $Credential.Password)

        xWaitForADDomain DscForestWait {
            DomainName = $Node.DomainName
            DomainUserCredential = $DomainCredential
            RetryCount = '20'
            RetryIntervalSec = '60'
        }

<#         xADComputer RemoveifExists {
            ComputerName = $Node.NodeName
            Ensure = "absent"
            DomainAdministratorCredential = $DomainCredential
            DependsOn = '[xWaitForADDomain]DSCForestWait'
        } #>

         xComputer JoinDC {
            Name = $Node.NodeName
            DomainName = $Node.DomainName
            Credential = $DomainCredential
            DependsOn = '[xWaitForADDomain]DSCForestWait'
        }
    }#end DomainJoin Config
#endregion

#region RSAT config
   node $AllNodes.Where({$_.Role -eq 'RSAT'}).NodeName {

    Script RSAT {
        # Adds RSAT which is now a Windows Capability in Windows 10
               TestScript = {
                   $rsat = @(
                       'Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0',
                       'Rsat.BitLocker.Recovery.Tools~~~~0.0.1.0',
                       'Rsat.CertificateServices.Tools~~~~0.0.1.0',
                       'Rsat.DHCP.Tools~~~~0.0.1.0',
                       'Rsat.Dns.Tools~~~~0.0.1.0',
                       'Rsat.FailoverCluster.Management.Tools~~~~0.0.1.0',
                       'Rsat.FileServices.Tools~~~~0.0.1.0',
                       'Rsat.GroupPolicy.Management.Tools~~~~0.0.1.0',
                       'Rsat.IPAM.Client.Tools~~~~0.0.1.0',
                       'Rsat.ServerManager.Tools~~~~0.0.1.0'
                   )
                   $packages = $rsat | ForEach-Object { Get-WindowsCapability -Online -Name $_ }
                   if ($packages.state -contains "NotPresent") {
                       Return $False
                   }
                   else {
                       Return $True
                   }
               } #test

               GetScript  = {
                   $rsat = @(
                       'Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0',
                       'Rsat.BitLocker.Recovery.Tools~~~~0.0.1.0',
                       'Rsat.CertificateServices.Tools~~~~0.0.1.0',
                       'Rsat.DHCP.Tools~~~~0.0.1.0',
                       'Rsat.Dns.Tools~~~~0.0.1.0',
                       'Rsat.FailoverCluster.Management.Tools~~~~0.0.1.0',
                       'Rsat.FileServices.Tools~~~~0.0.1.0',
                       'Rsat.GroupPolicy.Management.Tools~~~~0.0.1.0',
                       'Rsat.IPAM.Client.Tools~~~~0.0.1.0',
                       'Rsat.ServerManager.Tools~~~~0.0.1.0'
                   )
                   $packages = $rsat | ForEach-Object { Get-WindowsCapability -Online -Name $_ } | Select-Object Displayname, State
                   $installed = $packages.Where({ $_.state -eq "Installed" })
                   Return @{Result = "$($installed.count)/$($packages.count) RSAT features installed" }
               } #get

               SetScript  = {
                   $rsat = @(
                       'Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0',
                       'Rsat.BitLocker.Recovery.Tools~~~~0.0.1.0',
                       'Rsat.CertificateServices.Tools~~~~0.0.1.0',
                       'Rsat.DHCP.Tools~~~~0.0.1.0',
                       'Rsat.Dns.Tools~~~~0.0.1.0',
                       'Rsat.FailoverCluster.Management.Tools~~~~0.0.1.0',
                       'Rsat.FileServices.Tools~~~~0.0.1.0',
                       'Rsat.GroupPolicy.Management.Tools~~~~0.0.1.0',
                       'Rsat.IPAM.Client.Tools~~~~0.0.1.0',
                       'Rsat.ServerManager.Tools~~~~0.0.1.0'
                   )
                   foreach ($item in $rsat) {
                       $pkg = Get-WindowsCapability -Online -Name $item
                       if ($item.state -ne 'Installed') {
                           Add-WindowsCapability -Online -Name $item
                       }
                   }

               } #set

           } #rsat script resource

    } 
#endregion RSAT Config

#region RDP config
   node $AllNodes.Where({$_.Role -eq 'RDP'}).NodeName {
        # Adds RDP support and opens Firewall rules

        Registry RDP {
            Key = 'HKLM:\System\ControlSet001\Control\Terminal Server'
            ValueName = 'fDenyTSConnections'
            ValueType = 'Dword'
            ValueData = '0'
            Ensure = 'Present'
        }
        foreach ($Rule in @(
                'RemoteDesktop-UserMode-In-TCP',
                'RemoteDesktop-UserMode-In-UDP',
                'RemoteDesktop-Shadow-In-TCP'
        )) {
        xFirewall $Rule {
            Name = $Rule
            Enabled = 'True'
            DependsOn = '[Registry]RDP'
        }
    } # End RDP
    }
#endregion

#region ADCS

    node $AllNodes.Where({$_.Role -eq 'ADCS'}).NodeName {

        ## Hack to fix DependsOn with hypens "bug" :(
        foreach ($feature in @(
                'ADCS-Cert-Authority',
                'ADCS-Enroll-Web-Pol',
                'ADCS-Enroll-Web-Svc',
                'ADCS-Web-Enrollment'
                # For the GUI version - uncomment the following
                #'RSAT-ADCS',
                #'RSAT-ADCS-Mgmt'
            )) {

            WindowsFeature $feature.Replace('-','') {
                Ensure = 'Present';
                Name = $feature;
                IncludeAllSubFeature = $False;
                DependsOn = '[xADDomain]FirstDC'
            }
        } #End foreach

         xWaitForADDomain WaitForADADCSRole {
                DomainName = $Node.DomainName
                RetryIntervalSec = '30'
                RetryCount = '10'
                DomainUserCredential = $DomainCredential
                DependsOn = '[WindowsFeature]ADCSCertAuthority'
                }

        xAdcsCertificationAuthority ADCSConfig
        {
            CAType = $Node.ADCSCAType
            Credential = $Credential
            CryptoProviderName = $Node.ADCSCryptoProviderName
            HashAlgorithmName = $Node.ADCSHashAlgorithmName
            KeyLength = $Node.ADCSKeyLength
            CACommonName = $Node.CACN
            CADistinguishedNameSuffix = $Node.CADNSuffix
            DatabaseDirectory = $Node.CADatabasePath
            LogDirectory = $Node.CALogPath
            ValidityPeriod = $node.ADCSValidityPeriod
            ValidityPeriodUnits = $Node.ADCSValidityPeriodUnits
            DependsOn = '[xWaitForADDomain]WaitForADADCSRole'
        }

    #Add GPO for PKI AutoEnroll
        script CreatePKIAEGpo
        {
            Credential = $DomainCredential
            TestScript = {
                            if ((get-gpo -name "PKI AutoEnroll" -domain $Using:Node.DomainName -ErrorAction SilentlyContinue) -eq $Null) {
                                return $False
                            }
                            else {
                                return $True}
                        }
            SetScript = {
                            new-gpo -name "PKI AutoEnroll" -domain $Using:Node.DomainName
                        }
            GetScript = {
                            $GPO= (get-gpo -name "PKI AutoEnroll" -domain $Using:Node.DomainName)
                            return @{Result = $($GPO.DisplayName)}
                        }
            DependsOn = '[xWaitForADDomain]WaitForADADCSRole'
            }

        script setAEGPRegSetting1
        {
            Credential = $DomainCredential
            TestScript = {
                            if ((Get-GPRegistryValue -name "PKI AutoEnroll" -domain $Using:Node.DomainName -Key "HKLM\SOFTWARE\Policies\Microsoft\Cryptography\AutoEnrollment" -ValueName "AEPolicy" -ErrorAction SilentlyContinue).Value -eq 7) {
                                return $True
                            }
                            else {
                                return $False
                            }
                        }
            SetScript = {
                            Set-GPRegistryValue -name "PKI AutoEnroll" -domain $Using:Node.DomainName -Key "HKLM\SOFTWARE\Policies\Microsoft\Cryptography\AutoEnrollment" -ValueName "AEPolicy" -Value 7 -Type DWord
                        }
            GetScript = {
                            $RegVal1 = (Get-GPRegistryValue -name "PKI AutoEnroll" -domain $Using:Node.DomainName -Key "HKLM\SOFTWARE\Policies\Microsoft\Cryptography\AutoEnrollment" -ValueName "AEPolicy")
                            return @{Result = "$($RegVal1.FullKeyPath)\$($RegVal1.ValueName)\$($RegVal1.Value)"}
                        }
            DependsOn = '[Script]CreatePKIAEGpo'
        }

        script setAEGPRegSetting2
        {
            Credential = $DomainCredential
            TestScript = {
                            if ((Get-GPRegistryValue -name "PKI AutoEnroll" -domain $Using:Node.DomainName -Key "HKLM\SOFTWARE\Policies\Microsoft\Cryptography\AutoEnrollment" -ValueName "OfflineExpirationPercent" -ErrorAction SilentlyContinue).Value -eq 10) {
                                return $True
                                }
                            else {
                                return $False
                                 }
                         }
            SetScript = {
                            Set-GPRegistryValue -Name "PKI AutoEnroll" -domain $Using:Node.DomainName -Key "HKLM\SOFTWARE\Policies\Microsoft\Cryptography\AutoEnrollment" -ValueName "OfflineExpirationPercent" -value 10 -Type DWord
                        }
            GetScript = {
                            $Regval2 = (Get-GPRegistryValue -name "PKI AutoEnroll" -domain $Using:Node.DomainName -Key "HKLM\SOFTWARE\Policies\Microsoft\Cryptography\AutoEnrollment" -ValueName "OfflineExpirationPercent")
                            return @{Result = "$($RegVal2.FullKeyPath)\$($RegVal2.ValueName)\$($RegVal2.Value)"}
                        }
            DependsOn = '[Script]setAEGPRegSetting1'

        }

        script setAEGPRegSetting3
        {
            Credential = $DomainCredential
            TestScript = {
                            if ((Get-GPRegistryValue -Name "PKI AutoEnroll" -domain $Using:Node.DomainName -Key "HKLM\SOFTWARE\Policies\Microsoft\Cryptography\AutoEnrollment" -ValueName "OfflineExpirationStoreNames" -ErrorAction SilentlyContinue).value -match "MY") {
                                return $True
                                }
                            else {
                                return $False
                                }
                        }
            SetScript = {
                            Set-GPRegistryValue -Name "PKI AutoEnroll" -domain $Using:Node.DomainName -Key "HKLM\SOFTWARE\Policies\Microsoft\Cryptography\AutoEnrollment" -ValueName "OfflineExpirationStoreNames" -value "MY" -Type String
                        }
            GetScript = {
                            $RegVal3 = (Get-GPRegistryValue -Name "PKI AutoEnroll" -domain $Using:Node.DomainName -Key "HKLM\SOFTWARE\Policies\Microsoft\Cryptography\AutoEnrollment" -ValueName "OfflineExpirationStoreNames")
                            return @{Result = "$($RegVal3.FullKeyPath)\$($RegVal3.ValueName)\$($RegVal3.Value)"}
                        }
            DependsOn = '[Script]setAEGPRegSetting2'
        }

        Script SetAEGPLink
        {
            Credential = $DomainCredential
            TestScript = {
                            try {
                                $GPLink = (get-gpo -Name "PKI AutoEnroll" -Domain $Using:Node.DomainName).ID
                                $GPLinks = (Get-GPInheritance -Domain $Using:Node.DomainName -Target $Using:Node.DomainDN).gpolinks | Where-Object {$_.GpoID -like "*$GPLink*"}
                                if ($GPLinks.Enabled -eq $True) {return $True}
                                else {return $False}
                                }
                            catch {
                                Return $False
                                }
                         }
            SetScript = {
                            New-GPLink -name "PKI AutoEnroll" -domain $Using:Node.DomainName -Target $Using:Node.DomainDN -LinkEnabled Yes
                        }
            GetScript = {
                           $GPLink = (get-gpo -Name "PKI AutoEnroll" -Domain $Using:Node.DomainName).ID
                           $GPLinks = (Get-GPInheritance -Domain $Using:Node.DomainName -Target $Using:Node.DomainDN).gpolinks | Where-Object {$_.GpoID -like "*$GPLink*"}
                           return @{Result = "$($GPLinks.DisplayName) = $($GPLinks.Enabled)"}
                        }
            DependsOn = '[Script]setAEGPRegSetting3'
        }

#region Create and publish templates

#Note:  The Test section is pure laziness.  Future enhancement:  test for more than just existence.
        script CreateWebServer2Template
        {
            DependsOn = '[xAdcsCertificationAuthority]ADCSConfig'
            Credential = $DomainCredential
            TestScript = {
                            try {
                                $WSTemplate=get-ADObject -Identity "CN=WebServer2,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,$($Using:Node.DomainDN)" -Properties * -ErrorAction Stop
                                return $True
                                }
                            catch {
                                return $False
                                }
                         }
            SetScript = {
                         $WebServerTemplate = @{'flags'='131649';
                        'msPKI-Cert-Template-OID'='1.3.6.1.4.1.311.21.8.8211880.1779723.5195193.12600017.10487781.44.7319704.6725493';
                        'msPKI-Certificate-Application-Policy'='1.3.6.1.5.5.7.3.1';
                        'msPKI-Certificate-Name-Flag'='268435456';
                        'msPKI-Enrollment-Flag'='32';
                        'msPKI-Minimal-Key-Size'='2048';
                        'msPKI-Private-Key-Flag'='50659328';
                        'msPKI-RA-Signature'='0';
                        'msPKI-Supersede-Templates'='WebServer';
                        'msPKI-Template-Minor-Revision'='3';
                        'msPKI-Template-Schema-Version'='2';
                        'pKICriticalExtensions'='2.5.29.15';
                        'pKIDefaultCSPs'='2,Microsoft DH SChannel Cryptographic Provider','1,Microsoft RSA SChannel Cryptographic Provider';
                        'pKIDefaultKeySpec'='1';
                        'pKIExtendedKeyUsage'='1.3.6.1.5.5.7.3.1';
                        'pKIMaxIssuingDepth'='0';
                        'revision'='100'}


                        New-ADObject -name "WebServer2" -Type pKICertificateTemplate -Path "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,$($Using:Node.DomainDN)" -DisplayName WebServer2 -OtherAttributes $WebServerTemplate
                        $WSOrig = Get-ADObject -Identity "CN=WebServer,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,$($Using:Node.DomainDN)" -Properties * | Select-Object pkiExpirationPeriod,pkiOverlapPeriod,pkiKeyUsage
                        Get-ADObject -Identity "CN=WebServer2,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,$($Using:Node.DomainDN)" | Set-ADObject -Add @{'pKIKeyUsage'=$WSOrig.pKIKeyUsage;'pKIExpirationPeriod'=$WSOrig.pKIExpirationPeriod;'pkiOverlapPeriod'=$WSOrig.pKIOverlapPeriod}
                        }
                GetScript = {
                                try {
                                    $WS2=get-ADObject -Identity "CN=WebServer2,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,$($Using:Node.DomainDN)" -Properties * -ErrorAction Stop
                                    return @{Result=$WS2.DistinguishedName}
                                    }
                                catch {
                                    return @{Result=$Null}
                                    }
                            }
        }


 #Note:  The Test section is pure laziness.  Future enhancement:  test for more than just existence.
        script CreateDSCTemplate
        {
            DependsOn = '[xAdcsCertificationAuthority]ADCSConfig'
            Credential = $DomainCredential
            TestScript = {
                            try {
                                $DSCTemplate=get-ADObject -Identity "CN=DSCTemplate,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,$($Using:Node.DomainDN)" -Properties * -ErrorAction Stop
                                return $True
                                }
                            catch {
                                return $False
                                }
                         }
            SetScript = {
                         $DSCTemplateProps = @{'flags'='131680';
                        'msPKI-Cert-Template-OID'='1.3.6.1.4.1.311.21.8.16187918.14945684.15749023.11519519.4925321.197.13392998.8282280';
                        'msPKI-Certificate-Application-Policy'='1.3.6.1.4.1.311.80.1';
                        'msPKI-Certificate-Name-Flag'='1207959552';
                        #'msPKI-Enrollment-Flag'='34';
                        'msPKI-Enrollment-Flag'='32';
                        'msPKI-Minimal-Key-Size'='2048';
                        'msPKI-Private-Key-Flag'='0';
                        'msPKI-RA-Signature'='0';
                        #'msPKI-Supersede-Templates'='WebServer';
                        'msPKI-Template-Minor-Revision'='3';
                        'msPKI-Template-Schema-Version'='2';
                        'pKICriticalExtensions'='2.5.29.15';
                        'pKIDefaultCSPs'='1,Microsoft RSA SChannel Cryptographic Provider';
                        'pKIDefaultKeySpec'='1';
                        'pKIExtendedKeyUsage'='1.3.6.1.4.1.311.80.1';
                        'pKIMaxIssuingDepth'='0';
                        'revision'='100'}


                        New-ADObject -name "DSCTemplate" -Type pKICertificateTemplate -Path "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,$($Using:Node.DomainDN)" -DisplayName DSCTemplate -OtherAttributes $DSCTemplateProps
                        $WSOrig = Get-ADObject -Identity "CN=Workstation,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,$($Using:Node.DomainDN)" -Properties * | Select-Object pkiExpirationPeriod,pkiOverlapPeriod,pkiKeyUsage
                        [byte[]] $WSOrig.pkiKeyUsage = 48
                        Get-ADObject -Identity "CN=DSCTemplate,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,$($Using:Node.DomainDN)" | Set-ADObject -Add @{'pKIKeyUsage'=$WSOrig.pKIKeyUsage;'pKIExpirationPeriod'=$WSOrig.pKIExpirationPeriod;'pkiOverlapPeriod'=$WSOrig.pKIOverlapPeriod}
                        }
                GetScript = {
                                try {
                                    $dsctmpl = get-ADObject -Identity "CN=DSCTemplate,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,$($Using:Node.DomainDN)" -Properties * -ErrorAction Stop
                                    return @{Result=$dsctmpl.DistinguishedName}
                                    }
                                catch {
                                    return @{Result=$Null}
                                    }
                            }
        }

        script PublishWebServerTemplate2
        {
           DependsOn = '[Script]CreateWebServer2Template'
           Credential = $DomainCredential
           TestScript = {
                            $Template= Get-CATemplate | Where-Object {$_.Name -match "WebServer2"}
                            if ($Template -eq $Null) {return $False}
                            else {return $True}
                        }
           SetScript = {
                            add-CATemplate -name "WebServer2" -force
                        }
           GetScript = {
                            $pubWS2 = Get-CATemplate | Where-Object {$_.Name -match "WebServer2"}
                            return @{Result=$pubws2.Name}
                        }
         }

          script PublishDSCTemplate
        {
           DependsOn = '[Script]CreateDSCTemplate'
           Credential = $DomainCredential
           TestScript = {
                            $Template= Get-CATemplate | Where-Object {$_.Name -match "DSCTemplate"}
                            if ($Template -eq $Null) {return $False}
                            else {return $True}
                        }
           SetScript = {
                            add-CATemplate -name "DSCTemplate" -force
                            write-verbose -Message ("Publishing Template DSCTemplate...")
                        }
           GetScript = {
                            $pubDSC = Get-CATemplate | Where-Object {$_.Name -match "DSCTemplate"}
                            return @{Result=$pubDSC.Name}
                        }
         }


#endregion - Create and publish templates

#region template permissions
#Permission beginning with 0e10... is "Enroll".  Permission beginning with "a05b" is autoenroll.
#TODO:  Write-Verbose in other script resources.
#TODO:  Make $Perms a has table with GUID and permission name.  Use name in resource name.

        [string[]]$Perms = "0e10c968-78fb-11d2-90d4-00c04f79dc55","a05b8cc2-17bc-4802-a710-e7c15ab866a2"

        foreach ($P in $Perms) {

                script "Perms_WebCert_$($P)"
                {
                    DependsOn = '[Script]CreateWebServer2Template'
                    Credential = $DomainCredential
                    TestScript = {
                        Import-Module activedirectory -Verbose:$false
                        $WebServerCertACL = (get-acl "AD:CN=WebServer2,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,$($Using:Node.DomainDN)").Access | Where-Object {$_.IdentityReference -like "*Web Servers"}
                        if ($WebServerCertACL -eq $Null) {
                            write-verbose -message ("Web Servers Group does not have permissions on Web Server template...")
                            Return $False
                            }
                        elseif (($WebServerCertACL.ActiveDirectoryRights -like "*ExtendedRight*") -and ($WebServerCertACL.ObjectType -notcontains $Using:P)) {
                            write-verbose -message ("Web Servers group has permission, but not the correct permission...")
                            Return $False
                            }
                        else {
                            write-verbose -message ("ACL on Web Server Template is set correctly for this GUID for Web Servers Group...")
                            Return $True
                            }
                        }
                     SetScript = {
                        Import-Module activedirectory -Verbose:$false
                        $WebServersGroup = get-adgroup -Identity "Web Servers" | Select-Object SID
                        $EnrollGUID = [GUID]::Parse($Using:P)
                        $ACL = get-acl "AD:CN=WebServer2,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,$($Using:Node.DomainDN)"
                        $ACL.AddAccessRule((New-Object System.DirectoryServices.ExtendedRightAccessRule $WebServersGroup.SID,'Allow',$EnrollGUID,'None'))
                        #$ACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $WebServersGroup.SID,'ReadProperty','Allow'))
                        #$ACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $WebServersGroup.SID,'GenericExecute','Allow'))
                        set-ACL "AD:CN=WebServer2,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,$($Using:Node.DomainDN)" -AclObject $ACL
                        write-verbose -Message ("Permissions set for Web Servers Group")
                        }
                     GetScript = {
                        Import-Module activedirectory -Verbose:$false
                        $WebServerCertACL = (get-acl "AD:CN=WebServer2,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,$($Using:Node.DomainDN)").Access | Where-Object {$_.IdentityReference -like "*Web Servers"}
                        if ($WebServerCertACL -ne $Null) {
                            return @{Result=$WebServerCertACL}
                            }
                        else {
                            Return @{}
                            }
                        }
                 }

                script "Perms_DSCCert_$($P)"
                {
                    DependsOn = '[Script]CreateWebServer2Template'
                    Credential = $DomainCredential
                    TestScript = {
                        Import-Module activedirectory -Verbose:$false
                        $DSCCertACL = (get-acl "AD:CN=DSCTemplate,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,$($Using:Node.DomainDN)").Access | Where-Object {$_.IdentityReference -like "*Domain Computers*"}
                        if ($DSCCertACL -eq $Null) {
                            write-verbose -Message ("Domain Computers does not have permissions on DSC template")
                            Return $False
                            }
                        elseif (($DSCCertACL.ActiveDirectoryRights -like "*ExtendedRight*") -and ($DSCCertACL.ObjectType -notcontains $Using:P)) {
                            write-verbose -Message ("Domain Computers group has permission, but not the correct permission...")
                            Return $False
                            }
                        else {
                            write-verbose -Message ("ACL on DSC Template is set correctly for this GUID for Domain Computers...")
                            Return $True
                            }
                        }
                     SetScript = {
                        Import-Module activedirectory -Verbose:$false
                        $DomainComputersGroup = get-adgroup -Identity "Domain Computers" | Select-Object SID
                        $EnrollGUID = [GUID]::Parse($Using:P)
                        $ACL = get-acl "AD:CN=DSCTemplate,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,$($Using:Node.DomainDN)"
                        $ACL.AddAccessRule((New-Object System.DirectoryServices.ExtendedRightAccessRule $DomainComputersGroup.SID,'Allow',$EnrollGUID,'None'))
                        #$ACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $WebServersGroup.SID,'ReadProperty','Allow'))
                        #$ACL.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $WebServersGroup.SID,'GenericExecute','Allow'))
                        set-ACL "AD:CN=DSCTemplate,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,$($Using:Node.DomainDN)" -AclObject $ACL
                        write-verbose -Message ("Permissions set for Domain Computers...")
                        }
                     GetScript = {
                        Import-Module activedirectory -Verbose:$false
                        $DSCCertACL = (get-acl "AD:CN=WebServer2,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,$($Using:Node.DomainDN)").Access | Where-Object {$_.IdentityReference -like "*Domain Computers"}
                        if ($DSCCertACL -ne $Null) {
                            return @{Result=$DSCCertACL}
                            }
                        else {
                            Return @{}
                            }
                        }
                 }
      }

    } 
    
#endregion

#region ConfigMGR

node $AllNodes.Where({$_.Role -eq 'ConfigMgr'}).NodeName {

    $DomainCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ("$($node.DomainName)\$($Credential.UserName)", $Credential.Password)

    <#     
    xvmdvddrive AddISO {

        ControllerNumber   = 0
                ControllerLocation = 2 
                Path = "C:\Users\lelvi\Downloads\mul_microsoft_endpoint_configuration_manager_version_2203_x86_and_x64_dvd_38f456c8.iso"
                VMName = "S1"
    
    } #>


    

    WindowsFeatureSet WindowsFeatureSetExample
        {
            Name                    = @("RSAT-Role-Tools")
            Ensure                  = 'Present'
            IncludeAllSubFeature    = $true
        }

    File TempFolderExists {
        Type = 'Directory'
        DestinationPath = 'C:\Temp'
        Ensure = "Present"
    } 

    xADGroup CreateSCCMGroup {
        GroupName = "sccm-servers"
        Ensure      = 'Present'
        MembersToInclude = "CN=S1,OU=Servers,DC=Company,DC=Pri"
        Credential = $DomainCredential
        Path = "OU=SCCM,$($node.DomainDN)"
        DependsOn = "[xADOrganizationalUnit]CreateSCCM"
    }

    

    xADOrganizationalUnit CreateSCCM {
        Name = 'SCCM'
        Path = $Node.DomainDN
        Credential = $DomainCredential
        Description = 'The collection for all SCCM Objects'
        

    }
    
    xADUser CreateSCCM-SQLService {
        DomainName = $Node.Domainname
        UserName = 'SCCM-SQLService'
        DomainAdministratorCredential = $DomainCredential
        Path = "OU=SCCM,$($node.DomainDN)"
    }

    xADGroup CreateSCCMGroup02 {
        GroupName = "SCCM-CMInstall"
        Ensure      = 'Present'
        MembersToInclude = @("SCCM-SQLService")
        Credential = $DomainCredential
        Path = "OU=SCCM,$($node.DomainDN)"
        
    }

    $SccmInstallAccount = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ("$($node.DomainName)\SCCM-SQLService", $Credential.Password)
    
    xADUser CreateSCCM-Agent {
        DomainName = $Node.Domainname
        UserName = 'SCCM-SQLAgent'
        DomainAdministratorCredential = $DomainCredential
        Path = "OU=SCCM,$($node.DomainDN)"
    }
    
    
    $sccmSQLAGENTAccount = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ("$($node.DomainName)\SCCM-SQLAgent", $Credential.Password)


    
    
<#     LocalConfigurationManager
    {
        RebootNodeIfNeeded = $true
    } #>

    xPendingReboot RebootBeforeCCMInstall {
        Name = "RebootBeforeCCMInstall01"
    }

    # Hard-coding params to allow tests to pass. Remove these
    $ServerName = "S1.$($node.DomainName)"
    $SiteCode = 'PRI'
    $SiteName = "$($node.DomainNetBIOSNAME)"
    $ConfigMgrVersion = 2010
    $CMAccounts = @(
        New-Object System.Management.Automation.PSCredential("$($node.DomainNetBIOSNAME)\SCCM-Network", $(Convertto-SecureString -AsPlainText -String 'Generic' -Force))
        New-Object System.Management.Automation.PSCredential("$($node.DomainNetBIOSNAME)\SCCM-ClientPush", $(Convertto-SecureString -AsPlainText -String 'Generic' -Force))
        New-Object System.Management.Automation.PSCredential("$($node.DomainNetBIOSNAME)\SCCM-AdJoin", $(Convertto-SecureString -AsPlainText -String 'Generic' -Force))
    )

    $serverShortName = $ServerName.Split('.')[0]

    if ($serverShortName.Length -gt 4)
    {
        $dbInstanceName = $serverShortName.SubString($serverShortName.Length - 4) + "DB01"
    }
    else
    {
        $dbInstanceName = $serverShortName + "DB01"
    }

    if ($ConfigMgrVersion -lt '1910')
    {
        #$adkProductID = 'fb450356-9879-4b2e-8dc9-282709286661'
        $adkProductID = '665ec413-9c69-4696-b6d8-55d44bf46ac3'
        #$winPeProductID = 'd8369a05-1f4a-4735-9558-6e131201b1a2'
        $winPeProductID = '6775d5ee-c051-497c-aba6-344bbc5c896a'
    }
    else
    {
        #$adkProductID = '9346016b-6620-4841-8ea4-ad91d3ea02b5'
        $adkProductID = '665ec413-9c69-4696-b6d8-55d44bf46ac3'
        #$winPeProductID = '353df250-4ecc-4656-a950-4df93078a5fd'
        $winPeProductID = '6775d5ee-c051-497c-aba6-344bbc5c896a'
    }

    # SCCM PreReqs
    xSccmPreReqs SCCMPreReqs
    {
        InstallAdk             = $true
        InstallMdt             = $true
        AdkSetupExePath        = 'C:\Resources\ADKSETUP\ADK\adksetup.exe'
        AdkWinPeSetupPath      = 'C:\Resources\adkwinpesetup.exe'
        MdtMsiPath             = 'C:\Resources\MicrosoftDeploymentToolkit_x64.msi'
        InstallWindowsFeatures = $true
        WindowsFeatureSource   = 'C:\Windows\WinSxS'
        SccmRole               = 'CASorSiteServer','ManagementPoint','DistributionPoint','SoftwareUpdatePoint'
        LocalAdministrators    = @("$($node.DomainNetBIOSNAME)\SCCM-Servers","$($node.DomainNetBIOSNAME)\SCCM-CMInstall","$($node.DomainNetBIOSNAME)\Administrator")
        DomainCredential       = $DomainCredential
        AdkInstallPath         = 'C:\Apps\ADK'
        MdtInstallPath         = 'C:\Apps\MDT'
        AdkProductName         = 'Windows Assessment and Deployment Kit'
        AdkProductID           = $adkProductID
        AdkWinPeProductName    = 'Windows Assessment and Deployment Kit Windows Preinstallation Environment Add-ons'
        AdkWinPeProductID      = $winPeProductID
    }

    Firewall AddSccmTCPFirewallRule
    {
        Name        = 'SCCMServerTCP'
        DisplayName = 'SCCM to SCCM communication - TCP'
        Ensure      = 'Present'
        Enabled     = 'True'
        Profile     = 'Domain','Private'
        Direction   = 'Inbound'
        LocalPort   = '1433','1434','4022','445','135','139','49154-49157'
        Protocol    = 'TCP'
        Description = 'Firewall Rule SCCM to SCCM communication - TCP'
        DependsOn   = '[xSccmPreReqs]SCCMPreReqs'
    }

    Firewall AddSccmUdpFirewallRule
    {
        Name        = 'SCCMServerUDP'
        DisplayName = 'SCCM to SCCM communication - UDP'
        Ensure      = 'Present'
        Enabled     = 'True'
        Profile     = 'Domain','Private'
        Direction   = 'Inbound'
        LocalPort   = '137-138','1434','5355'
        Protocol    = 'UDP'
        Description = 'Firewall Rule SCCM to SCCM communication - UDP'
        DependsOn   = '[Firewall]AddSccmTCPFirewallRule'
    }

    SQLSetup SCCMSqlInstall
    {
        Features            = 'SQLEngine,RS,CONN,BC,TOOLS'
        InstallSharedDir    = 'C:\Apps\Microsoft SQL Server'
        InstallSharedWowDir = 'C:\Apps (x86)\Microsoft SQL Server'
        InstanceDir         = 'C:\Apps\Microsoft SQL Server'
        InstanceName        = $dbInstanceName
        SQLSvcAccount       = $SccmInstallAccount
        AgtSvcAccount       = $sccmSQLAGENTAccount
        RSInstallMode       = 'DefaultNativeMode'
        RSSVCStartUpType    = 'Automatic'
        AgtSvcStartupType   = 'Automatic'
        SQLCollation        = 'SQL_Latin1_General_CP1_CI_AS'
        SQLSysAdminAccounts = @("$($node.DomainNetBIOSNAME)\SCCM-Servers","$($node.DomainNetBIOSNAME)\Administrator","$($node.DomainNetBIOSNAME)\SCCM-CMInstall")
        InstallSQLDataDir   = 'C:'
        SQLUserDBDir        = "C:\MSSQL12.$dbInstanceName\MSSQL\Data\App"
        SQLUserDBLogDir     = "C:\MSSQL12.$dbInstanceName\MSSQL\Log\App"
        SQLTempDBDir        = "C:\MSSQL12.$dbInstanceName\MSSQL\Data\System"
        SQLTempDBLogDir     = "C:\MSSQL12.$dbInstanceName\MSSQL\Log\System"
        SourcePath          = 'D:\'
        UpdateEnabled       = $false
        DependsOn           = '[Firewall]AddSccmUdpFirewallRule'
        

    }

    SqlServerNetwork EnableTcpIp
    {
        InstanceName   = $dbInstanceName
        ProtocolName   = 'Tcp'
        IsEnabled      = $true
        TcpPort        = 1433
        RestartService = $true
        DependsOn      = '[SqlSetup]SCCMSqlInstall'
    }

    Package InstallSSMS {
        Name = 'SSMS-Setup-ENU'
        Path = "C:\Resources\SSMS-Setup-ENU.exe"
        Arguments = "/install /passive /norestart"
        ProductId = ''
        ReturnCode = 1856439871
    }

    # WSUS registry value to fix issues with WSUS self-signed certificates
    Registry EnableWSUSSelfSignedCert
    {
        Ensure    = 'Present'
        Key       = 'HKLM:\Software\Microsoft\Update Services\Server\Setup'
        ValueName = 'EnableSelfSignedCertificates'
        ValueData = '1'
        ValueType = 'Dword'
    }

    File WSUSUpdates
    {
        DestinationPath = 'C:\Apps\WSUS'
        Ensure          = 'Present'
        Type            = 'Directory'
    }

    UpdateServicesServer WSUSConfig
    {
        Ensure            = 'Present'
        SQLServer         = "$($Node.NodeName)\$dbInstanceName"
        ContentDir        = 'C:\Apps\WSUS'
        Products          = '*'
        Classifications   = '*'
        UpstreamServerSSL = $false
        Synchronize       = $false
        DependsOn         = '[File]WSUSUpdates','[Firewall]AddSccmUdpFirewallRule','[Registry]EnableWSUSSelfSignedCert'
    }

    File CreateIniFolder
    {
        Ensure          = 'Present'
        Type            = 'Directory'
        DestinationPath = 'C:\SetupFiles'
        DependsOn       = '[SQLSetup]SCCMSqlInstall'
    }

    CMIniFile CreateSCCMIniFile
    {
        IniFileName               = 'Demo.ini'
        IniFilePath               = 'C:\SetupFiles\'
        Action                    = 'InstallPrimarySite'
        CDLatest                  = $false
        ProductID                 = 'eval'
        SiteCode                  = $SiteCode
        SiteName                  = "$SiteName - Primary Site"
        SMSInstallDir             = 'C:\Apps\Microsoft Configuration Manager'
        SDKServer                 = $ServerName
        RoleCommunicationProtocol = 'HTTPorHTTPS'
        ClientsUsePKICertificate  = $true
        PreRequisiteComp          = $true
        PreRequisitePath          = 'C:\temp\SCCMInstall\Downloads'
        AdminConsole              = $true
        JoinCeip                  = $false
        MobileDeviceLanguage      = $false
        SQLServerName             = $ServerName
        DatabaseName              = "$dbInstanceName\CM_$SiteCode"
        SQLSSBPort                = 4022
        SQLDataFilePath           = "C:\MSSQL12.$dbInstanceName\MSSQL\Data\"
        SQLLogFilePath            = "C:\MSSQL12.$dbInstanceName\MSSQL\Log\"
        CloudConnector            = $false
        SAActive                  = $true
        CurrentBranch             = $true
        DependsOn                 = '[File]CreateIniFolder'
    }

<#     
    xvmdvddrive AddISO {

        ControllerNumber   = 0
                ControllerLocation = 2 
                Path = "C:\Users\lelvi\Downloads\mul_microsoft_endpoint_configuration_manager_version_2203_x86_and_x64_dvd_38f456c8.iso"
                VMName = "S1"
    
    } #>

    xSccmInstall SccmInstall
    {
        SetupExePath       = 'E:\SMSSETUP\BIN\X64'
        IniFile            = 'C:\SetupFiles\Demo.ini'
        SccmServerType     = 'Primary'
        SccmInstallAccount = $SccmInstallAccount
        Version            = $ConfigMgrVersion
        DependsOn          = '[CMIniFile]CreateSCCMIniFile'
    }

    # Ensuring the machine reboots after SCCM install in order to be sure configurations proceed properly
    Script RebootAfterSccmSetup
    {
        TestScript = {
            return (Test-Path HKLM:\SOFTWARE\Microsoft\SMS\RebootAfterSCCMSetup)
        }
        SetScript  = {
            $process = Get-Process | Where-Object -FilterScript {$_.Description -eq 'Configuration Manager Setup BootStrapper'}

            if ([string]::IsNullOrEmpty($process))
            {
                Write-Verbose -Message "SCCM has finished installing setting reboot"
                New-Item -Path HKLM:\SOFTWARE\Microsoft\SMS\RebootAfterSCCMSetup -Force
                $global:DSCMachineStatus = 1
            }
            else
            {
                throw 'Configuration Manager setup is still running'
            }
        }
        GetScript  = { return @{result = 'result'}}
        DependsOn  = '[xSccmInstall]SccmInstall'
    }

    # region ConfigCBMgr configurations
    foreach ($account in $CMAccounts)
    {
        CMAccounts "AddingAccount-$($account.Username)"
        {
            SiteCode             = $SiteCode
            Account              = $account.Username
            AccountPassword      = $account
            Ensure               = 'Present'
            PsDscRunAsCredential = $SccmInstallAccount
            DependsOn            = '[Script]RebootAfterSccmSetup'
        }

        [array]$cmAccountsDependsOn += "[CMAccounts]AddingAccount-$($account.Username)"
    }

    CMEmailNotificationComponent EmailSettings
    {
        SiteCode             = $SiteCode
        SendFrom             = 'emailsender@contoso.com'
        SmtpServerFqdn       = 'EmailServer.contoso.com'
        TypeOfAuthentication = 'Other'
        Port                 = 465
        UseSsl               = $true
        Enabled              = $true
        UserName             = "$($node.DomainNetBIOSNAME)\EmailUser"
        PsDscRunAsCredential = $SccmInstallAccount
        DependsOn            = $cmAccountsDependsOn
    }

    CMForestDiscovery CreateForestDiscovery
    {
        SiteCode             = $SiteCode
        Enabled              = $false
        PsDscRunAsCredential = $SccmInstallAccount
        DependsOn            = '[Script]RebootAfterSccmSetup'
    }

    CMSystemDiscovery CreateSystemDiscovery
    {
        SiteCode                        = $SiteCode
        Enabled                         = $true
        ScheduleInterval                = 'Days'
        ScheduleCount                   = 7
        EnableDeltaDiscovery            = $true
        DeltaDiscoveryMins              = 60
        EnableFilteringExpiredLogon     = $true
        TimeSinceLastLogonDays          = 90
        EnableFilteringExpiredPassword  = $true
        TimeSinceLastPasswordUpdateDays = 90
        ADContainers                    = @("LDAP://OU=Domain Controllers,$($Node.DomainDN)","LDAP://CN=Computers,$($Node.DomainDN)")
        PsDscRunAsCredential            = $SccmInstallAccount
        DependsOn                       = '[Script]RebootAfterSccmSetup'
    }

    CMNetworkDiscovery DisableNetworkDiscovery
    {
        SiteCode             = $SiteCode
        Enabled              = $false
        PsDscRunAsCredential = $SccmInstallAccount
        DependsOn            = '[Script]RebootAfterSccmSetup'
    }

    CMHeartbeatDiscovery CreateHeartbeatDiscovery
    {
        SiteCode             = $SiteCode
        Enabled              = $true
        ScheduleInterval     = 'Days'
        ScheduleCount        = '1'
        PsDscRunAsCredential = $SccmInstallAccount
        DependsOn            = '[Script]RebootAfterSccmSetup'
    }

    CMUserDiscovery CreateUserDiscovery
    {
        SiteCode             = $SiteCode
        Enabled              = $true
        ScheduleInterval     = 'Days'
        ScheduleCount        = 7
        EnableDeltaDiscovery = $true
        DeltaDiscoveryMins   = 5
        ADContainers         = @("LDAP://CN=Users,$($Node.DomainDN)")
        PsDscRunAsCredential = $SccmInstallAccount
        DependsOn            = '[Script]RebootAfterSccmSetup'
    }

    CMClientStatusSettings CreateClientStatusSettings
    {
        SiteCode               = $SiteCode
        IsSingleInstance       = 'Yes'
        ClientPolicyDays       = 7
        HeartbeatDiscoveryDays = 7
        SoftwareInventoryDays  = 7
        HardwareInventoryDays  = 7
        StatusMessageDays      = 7
        HistoryCleanupDays     = 31
        PsDscRunAsCredential   = $SccmInstallAccount
        DependsOn              = '[Script]RebootAfterSccmSetup'
    }

    File CreateBackupFolder
    {
        Ensure          = 'Present'
        Type            = 'Directory'
        DestinationPath = 'C:\cmsitebackups'
    }

    CMSiteMaintenance Backup
    {
        SiteCode             = $SiteCode
        TaskName             = 'Backup SMS Site Server'
        Enabled              = $true
        DaysOfWeek           = @('Sunday','Monday','Tuesday','Wednesday','Thursday','Friday','Saturday')
        BeginTime            = '1500'
        LatestBeginTime      = '2000'
        BackupLocation       = 'C:\cmsitebackups'
        PsDscRunAsCredential = $SccmInstallAccount
        DependsOn            = '[Script]RebootAfterSccmSetup','[File]CreateBackupFolder'
    }

    [array]$cmSiteMaintenanceDependsOn += '[CMSiteMaintenance]Backup'

    CMSiteMaintenance DeleteEP
    {
        SiteCode             = $SiteCode
        TaskName             = 'Delete Aged EP Health Status History Data'
        Enabled              = $false
        PsDscRunAsCredential = $SccmInstallAccount
        DependsOn            = '[Script]RebootAfterSccmSetup'
    }

    [array]$cmSiteMaintenanceDependsOn += '[CMSiteMaintenance]DeleteEP'

    CMSiteMaintenance UpdateAppTables
    {
        SiteCode             = $SiteCode
        TaskName             = 'Update Application Catalog Tables'
        Enabled              = $true
        RunInterval          = 1380
        PsDscRunAsCredential = $SccmInstallAccount
        DependsOn            = '[Script]RebootAfterSccmSetup'
    }

    [array]$cmSiteMaintenanceDependsOn += '[CMSiteMaintenance]UpdateAppTables'

    CMSiteMaintenance InactiveDisco
    {
        SiteCode             = $SiteCode
        TaskName             = 'Delete Inactive Client Discovery Data'
        Enabled              = $true
        DaysOfWeek           = 'Saturday'
        DeleteOlderThanDays  = 90
        BeginTime            = '1500'
        LatestBeginTime      = '2000'
        PsDscRunAsCredential = $SccmInstallAccount
        DependsOn            = '[Script]RebootAfterSccmSetup'
    }

    [array]$cmSiteMaintenanceDependsOn += '[CMSiteMaintenance]InactiveDisco'

    CMBoundaries DemoBoundary
    {
        SiteCode             = $SiteCode
        DisplayName          = 'Contoso Boundary'
        Value                = '10.10.1.1-10.10.1.254'
        Type                 = 'IPRange'
        PsDscRunAsCredential = $SccmInstallAccount
        DependsOn            = '[Script]RebootAfterSccmSetup'
    }

    CMBoundaryGroups DemoBoundaryGroup
    {
        SiteCode             = $SiteCode
        BoundaryGroup        = 'Contoso BoundaryGroup'
        Boundaries           = @(
            DSC_CMBoundaryGroupsBoundaries
            {
                Value = '10.10.1.1-10.10.1.254'
                Type  = 'IPRange'
            }
        )
        SiteSystemsToInclude = @($ServerName)
        PsDscRunAsCredential = $SccmInstallAccount
        DependsOn            = '[CMBoundaries]DemoBoundary'
    }

    CMAdministrativeUser SiteAdmins
    {
        SiteCode        = $SiteCode
        AdminName       = 'Contoso\SCCM-SiteAdmins'
        RolesToInclude  = 'Full Administrator'
        ScopesToInclude = 'All'
        Ensure          = 'Present'
        DependsOn       = '[Script]RebootAfterSccmSetup'
    }

    CMCollectionMembershipEvaluationComponent CollectionSettings
    {
        SiteCode             = $SiteCode
        EvaluationMins       = 5
        PsDscRunAsCredential = $SccmInstallAccount
        DependsOn            = '[Script]RebootAfterSccmSetup'
    }

    CMStatusReportingComponent StatusReportingSettings
    {
        SiteCode                   = $SiteCode
        ClientLogChecked           = $false
        ClientLogFailureChecked    = $false
        ClientReportChecked        = $true
        ClientReportFailureChecked = $true
        ClientReportType           = 'AllMilestones'
        ServerLogChecked           = $false
        ServerLogFailureChecked    = $false
        ServerReportChecked        = $true
        ServerReportFailureChecked = $true
        ServerReportType           = 'AllMilestones'
        PsDscRunAsCredential       = $SccmInstallAccount
        DependsOn                  = '[Script]RebootAfterSccmSetup'
    }

    Registry MaxHWMifSize
    {
        Ensure    = 'Present'
        Key       = 'HKLM:\Software\Microsoft\SMS\Components\SMS_Inventory_Data_Loader'
        ValueName = 'Max MIF Size'
        ValueData = 500000000
        ValueType = 'Dword'
        DependsOn = '[Script]RebootAfterSccmSetup'
    }

    CMDistributionGroup DistroPtGroup
    {
        SiteCode             = $SiteCode
        DistributionGroup    = "$SiteCode - All Distribution Points"
        Ensure               = 'Present'
        PsDscRunAsCredential = $SccmInstallAccount
        DependsOn            = '[Script]RebootAfterSccmSetup'
    }

    CMDistributionPoint DPRole
    {
        SiteCode                = $SiteCode
        SiteServerName          = $ServerName
        Description             = 'Standard Distribution Point'
        MinimumFreeSpaceMB      = 100
        BoundaryGroups          = @('Contoso BoundaryGroup')
        BoundaryGroupStatus     = 'Add'
        AllowPrestaging         = $false
        EnableAnonymous         = $true
        EnableBranchCache       = $true
        EnableLedbat            = $true
        ClientCommunicationType = 'Http'
        PsDscRunAsCredential    = $SccmInstallAccount
        DependsOn               = '[CMDistributionGroup]DistroPtGroup'
    }

    CMDistributionPointGroupMembers DPGroupMembers
    {
        SiteCode                    = $SiteCode
        DistributionPoint           = $ServerName
        DistributionGroupsToInclude = @("$SiteCode - All Distribution Points")
        PsDscRunAsCredential        = $SccmInstallAccount
        DependsOn                   = "[CMDistributionPoint]DPRole"
    }

    CMManagementPoint MPInstall
    {
        SiteCode             = $SiteCode
        SiteServerName       = $ServerName
        Ensure               = 'Present'
        GenerateAlert        = $true
        UseSiteDatabase      = $true
        UseComputerAccount   = $true
        PsDscRunAsCredential = $SccmInstallAccount
        DependsOn            = '[Script]RebootAfterSccmSetup'
    }

    CMSoftwareUpdatePoint SUPInstall
    {
        SiteCode                      = $SiteCode
        SiteServerName                = $ServerName
        ClientConnectionType          = 'Intranet'
        EnableCloudGateway            = $false
        UseProxy                      = $false
        UseProxyForAutoDeploymentRule = $false
        WsusIisPort                   = '8530'
        WsusIisSslPort                = '8531'
        WsusSsl                       = $false
        PsDscRunAsCredential          = $SccmInstallAccount
        DependsOn                     = '[Script]RebootAfterSccmSetup'
    }

    CMSoftwareUpdatePointComponent SUPComponent
    {
        SiteCode                                = $SiteCode
        EnableSynchronization                   = $true
        SynchronizeAction                       = 'SynchronizeFromMicrosoftUpdate'
        ScheduleType                            = 'Days'
        RecurInterval                           = 7
        LanguageSummaryDetailsToInclude         = @('English')
        LanguageUpdateFilesToInclude            = @('English')
        ProductsToInclude                       = @('Windows 10')
        UpdateClassificationsToInclude          = @('Critical Updates','Updates')
        ContentFileOption                       = 'FullFilesOnly'
        DefaultWsusServer                       = $ServerName
        EnableCallWsusCleanupWizard             = $true
        EnableSyncFailureAlert                  = $true
        ImmediatelyExpireSupersedence           = $false
        ImmediatelyExpireSupersedenceForFeature = $false
        ReportingEvent                          = 'DoNotCreateWsusReportingEvents'
        WaitMonth                               = 1
        WaitMonthForFeature                     = 1
        EnableThirdPartyUpdates                 = $true
        EnableManualCertManagement              = $false
        FeatureUpdateMaxRuntimeMins             = 300
        NonFeatureUpdateMaxRuntimeMins          = 300
        DependsOn                               = '[CMSoftwareUpdatePoint]SUPInstall'
    }

    Script RebootAfterSCCMConfigurationInstall
    {
        TestScript = {
            return (Test-Path HKLM:\SOFTWARE\Microsoft\SMS\RebbotAfterConfiguration)
        }
        SetScript  = {
            New-Item -Path HKLM:\SOFTWARE\Microsoft\SMS\RebbotAfterConfiguration -Force
            $global:DSCMachineStatus = 1
        }
        GetScript  = { return @{result = 'result'}}
        DependsOn  = $cmAccountsDependsOn,'[CMForestDiscovery]CreateForestDiscovery','[CMSystemDiscovery]CreateSystemDiscovery','[CMNetworkDiscovery]DisableNetworkDiscovery',
            '[CMHeartbeatDiscovery]CreateHeartbeatDiscovery','[CMUserDiscovery]CreateUserDiscovery','[CMClientStatusSettings]CreateClientStatusSettings',$cmSiteMaintenanceDependsOn,
            '[CMBoundaryGroups]DemoBoundaryGroup','[CMAdministrativeUser]SiteAdmins','[CMCollectionMembershipEvaluationComponent]CollectionSettings',
            '[CMStatusReportingComponent]StatusReportingSettings','[Registry]MaxHWMifSize','[CMDistributionPointGroupMembers]DPGroupMembers','[CMManagementPoint]MPInstall',
            '[CMSoftwareUpdatePoint]SUPInstall','[CMEmailNotificationComponent]EmailSettings','[CMSoftwareUpdatePointComponent]SUPComponent'
    }


}


#endregion ConfigMgr


    node $Allnodes.Where({ 'Firefox' -in $_.Lability_Resource }).NodeName {
        Script "InstallFirefox" {
            GetScript            = { return @{ Result = "" } }
            TestScript           = {
                Test-Path -Path "C:\Program Files\Mozilla Firefox"
            }
            SetScript            = {
                $process = Start-Process -FilePath "C:\Resources\Firefox-Latest.exe" -Wait -PassThru -ArgumentList @('-ms')
                if ($process.ExitCode -ne 0) {
                    throw "Firefox installer at $ffInstaller exited with code $($process.ExitCode)"
                }
            }
            PsDscRunAsCredential = $Credential
        }
    }

    node $Allnodes.Where({ 'UcmaRuntimeSetup' -in $_.Lability_Resource }).NodeName {
        Script "InstallUcmaRuntimeSetup" {
            GetScript            = { return @{ Result = "" } }
            TestScript           = {
                Test-Path -Path "C:\Program Files\Microsoft UCMA 4.0"
            }
            SetScript            = {
                $process = Start-Process -FilePath "C:\Resources\UcmaRuntimeSetup.exe" -Wait -PassThru -ArgumentList @('-q')
                if ($process.ExitCode -ne 0) {
                    throw "UcmaRuntimeSetup installer at $ffInstaller exited with code $($process.ExitCode)"
                }
            }
            PsDscRunAsCredential = $Credential
        }
    }

    node $Allnodes.Where({ 'GoogleChrome' -in $_.Lability_Resource }).NodeName {
        Script "InstallGoogleChrome" {
            GetScript            = { return @{ Result = "" } }
            TestScript           = {
                Test-Path -Path "C:\Program Files\Google Chrome"
            }
            SetScript            = {
                $process = Start-Process -FilePath "C:\Windows\System32\msiexec.exe" -Wait -PassThru -ArgumentList @('/i C:\Resources\googlechromestandaloneenterprise64.msi /Q')
                if ($process.ExitCode -ne 0) {
                    throw "Google Chrome installer at $ffInstaller exited with code $($process.ExitCode)"
                }
            }
            PsDscRunAsCredential = $Credential
        }
    }

    node $Allnodes.Where({ 'URLREWRITE' -in $_.Lability_Resource }).NodeName {
        Script "InstallURLREWRITE" {
            GetScript            = { return @{ Result = "" } }
            TestScript           = {
                Test-Path -Path "C:\Program Files\Google Chrome"
            }
            SetScript            = {
                $process = Start-Process -FilePath "C:\Windows\System32\msiexec.exe" -Wait -PassThru -ArgumentList @('/i C:\Resources\rewrite_amd64_en-US.msi /Q')
                if ($process.ExitCode -ne 0) {
                    throw "URLREWRITE installer at $ffInstaller exited with code $($process.ExitCode)"
                }
            }
            PsDscRunAsCredential = $Credential
        }
    }

    node $Allnodes.Where({ 'Visual Studio 2013 x86' -in $_.Lability_Resource }).NodeName {
        Script "Install" {
            GetScript            = { return @{ Result = "" } }
            TestScript           = {
                Test-Path -Path "C:\Program Files\Google Chrome"
            }
            SetScript            = {
                $process = Start-Process -FilePath "C:\Resources\vcredist_2013_x86.exe" -Wait -PassThru -ArgumentList @('-q')
                if ($process.ExitCode -ne 0) {
                    throw "URLREWRITE installer at $ffInstaller exited with code $($process.ExitCode)"
                }
            }
            PsDscRunAsCredential = $Credential
        }
    }

    
} # End AllNodes
#endregion

AutoLab -OutputPath $PSScriptRoot -ConfigurationData $PSScriptRoot\VMConfigurationData.psd1

