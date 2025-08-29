# Microsoft Enterprise Access Model GPO DSC Resource
# This resource creates and applies Group Policy Objects for Tier 0 and Tier 1 requirements

Configuration MicrosoftEnterpriseAccessModelGPO {
    param(
        [Parameter(Mandatory=$true)]
        [ValidateSet("Tier0", "Tier1")]
        [string]$TierLevel,
        
        [Parameter(Mandatory=$true)]
        [string]$DomainName,
        
        [Parameter(Mandatory=$true)]
        [string]$TargetOU,
        
        [Parameter(Mandatory=$false)]
        [string]$GPOBackupPath = "C:\GPOBackups",
        
        [Parameter(Mandatory=$false)]
        [bool]$EnableCredentialGuard = $true,
        
        [Parameter(Mandatory=$false)]
        [bool]$EnableDeviceGuard = $true,
        
        [Parameter(Mandatory=$false)]
        [string[]]$Tier0AdminGroups = @("Domain Admins", "Enterprise Admins"),
        
        [Parameter(Mandatory=$false)]
        [string[]]$Tier1AdminGroups = @("Server Operators", "Print Operators")
    )

    $LabData = Import-PowerShellDataFile -Path $PSScriptRoot\*.psd1
    
    Import-DscResource -ModuleName PSDesiredStateConfiguration
    
    Node localhost {
        
        # Ensure Group Policy Management Tools are installed
        WindowsFeature GPMCFeature {
            Name = "GPMC"
            Ensure = "Present"
        }
        
        WindowsFeature RSATADPowerShell {
            Name = "RSAT-AD-PowerShell"
            Ensure = "Present"
        }
        
        # Create backup directory for GPO exports
        File GPOBackupDirectory {
            DestinationPath = $GPOBackupPath
            Type = "Directory"
            Ensure = "Present"
        }
        
        # Script resource to create and configure GPOs
        Script CreateEnterpriseAccessModelGPO {
            GetScript = {
                $gpoName = "EAM-$using:TierLevel-Security-Policy"
                try {
                    $gpo = Get-GPO -Name $gpoName -ErrorAction Stop
                    return @{
                        Result = "GPO exists: $($gpo.DisplayName)"
                        GPOExists = $true
                    }
                } catch {
                    return @{
                        Result = "GPO does not exist"
                        GPOExists = $false
                    }
                }
            }
            
            TestScript = {
                $gpoName = "EAM-$using:TierLevel-Security-Policy"
                try {
                    $gpo = Get-GPO -Name $gpoName -ErrorAction Stop
                    $link = Get-GPLink -Target $using:TargetOU -ErrorAction SilentlyContinue
                    return ($gpo -ne $null -and $link -ne $null)
                } catch {
                    return $false
                }
            }
            
            SetScript = {
                Import-Module GroupPolicy
                Import-Module ActiveDirectory
                
                $gpoName = "EAM-$using:TierLevel-Security-Policy"
                $domain = $using:DomainName
                $targetOU = $using:TargetOU
                $tierLevel = $using:TierLevel
                $enableCredGuard = $using:EnableCredentialGuard
                $enableDevGuard = $using:EnableDeviceGuard
                $tier0AdminGroups = $using:Tier0AdminGroups
                $tier1AdminGroups = $using:Tier1AdminGroups
                
                # Create the GPO
                Write-Verbose "Creating GPO: $gpoName"
                $gpo = New-GPO -Name $gpoName -Domain $domain -Comment "Enterprise Access Model $tierLevel security requirements"
                
                # Common security settings for both tiers
                Write-Verbose "Configuring common security settings..."
                
                # Account Policies
                Set-GPRegistryValue -Name $gpoName -Key "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" -ValueName "LimitBlankPasswordUse" -Type DWord -Value 1
                Set-GPRegistryValue -Name $gpoName -Key "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" -ValueName "NoLMHash" -Type DWord -Value 1
                Set-GPRegistryValue -Name $gpoName -Key "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" -ValueName "RunAsPPL" -Type DWord -Value 1
                Set-GPRegistryValue -Name $gpoName -Key "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -ValueName "UseLogonCredential" -Type DWord -Value 0
                
                # Network security
                Set-GPRegistryValue -Name $gpoName -Key "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -ValueName "RequireSecuritySignature" -Type DWord -Value 1
                Set-GPRegistryValue -Name $gpoName -Key "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -ValueName "RequireSecuritySignature" -Type DWord -Value 1
                Set-GPRegistryValue -Name $gpoName -Key "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -ValueName "NtlmMinClientSec" -Type DWord -Value 537395200
                Set-GPRegistryValue -Name $gpoName -Key "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -ValueName "NtlmMinServerSec" -Type DWord -Value 537395200
                
                # Disable legacy protocols
                Set-GPRegistryValue -Name $gpoName -Key "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server" -ValueName "Enabled" -Type DWord -Value 0
                Set-GPRegistryValue -Name $gpoName -Key "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server" -ValueName "Enabled" -Type DWord -Value 0
                Set-GPRegistryValue -Name $gpoName -Key "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" -ValueName "Enabled" -Type DWord -Value 0
                Set-GPRegistryValue -Name $gpoName -Key "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" -ValueName "Enabled" -Type DWord -Value 0
                
                # Enable TLS 1.2
                Set-GPRegistryValue -Name $gpoName -Key "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" -ValueName "Enabled" -Type DWord -Value 1
                Set-GPRegistryValue -Name $gpoName -Key "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client" -ValueName "Enabled" -Type DWord -Value 1
                
                # Disable weak ciphers
                Set-GPRegistryValue -Name $gpoName -Key "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 128/128" -ValueName "Enabled" -Type DWord -Value 0
                Set-GPRegistryValue -Name $gpoName -Key "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 40/128" -ValueName "Enabled" -Type DWord -Value 0
                Set-GPRegistryValue -Name $gpoName -Key "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 56/128" -ValueName "Enabled" -Type DWord -Value 0
                
                # Enhanced logging
                Set-GPRegistryValue -Name $gpoName -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -ValueName "EnableModuleLogging" -Type DWord -Value 1
                Set-GPRegistryValue -Name $gpoName -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -ValueName "EnableScriptBlockLogging" -Type DWord -Value 1
                Set-GPRegistryValue -Name $gpoName -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -ValueName "ProcessCreationIncludeCmdLine_Enabled" -Type DWord -Value 1
                
                # Disable PowerShell v2
                Set-GPRegistryValue -Name $gpoName -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\v1\PowerShellEngine" -ValueName "PowerShellVersion" -Type DWord -Value 0
                
                # Security options
                Set-GPRegistryValue -Name $gpoName -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ValueName "DontDisplayLastUserName" -Type DWord -Value 1
                Set-GPRegistryValue -Name $gpoName -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ValueName "DisableCAD" -Type DWord -Value 0
                Set-GPRegistryValue -Name $gpoName -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -ValueName "NoDriveTypeAutoRun" -Type DWord -Value 255
                Set-GPRegistryValue -Name $gpoName -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -ValueName "NoAutoplayfornonVolume" -Type DWord -Value 1
                
                # Tier-specific configurations
                if ($tierLevel -eq "Tier0") {
                    Write-Verbose "Applying Tier 0 specific settings..."
                    
                    # Credential Guard
                    if ($enableCredGuard) {
                        Set-GPRegistryValue -Name $gpoName -Key "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" -ValueName "EnableVirtualizationBasedSecurity" -Type DWord -Value 1
                        Set-GPRegistryValue -Name $gpoName -Key "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" -ValueName "LsaCfgFlags" -Type DWord -Value 1
                        Set-GPRegistryValue -Name $gpoName -Key "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" -ValueName "ConfigureSystemGuardLaunch" -Type DWord -Value 1
                    }
                    
                    # Restrict anonymous access
                    Set-GPRegistryValue -Name $gpoName -Key "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" -ValueName "RestrictAnonymousSAM" -Type DWord -Value 1
                    Set-GPRegistryValue -Name $gpoName -Key "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" -ValueName "RestrictAnonymous" -Type DWord -Value 1
                    
                    # Disable SMB1
                    Set-GPRegistryValue -Name $gpoName -Key "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -ValueName "SMB1" -Type DWord -Value 0
                    
                    # Additional Tier 0 hardening
                    Set-GPRegistryValue -Name $gpoName -Key "HKLM\SYSTEM\CurrentControlSet\Services\RasMan\Parameters" -ValueName "DisableSavePassword" -Type DWord -Value 1
                    Set-GPRegistryValue -Name $gpoName -Key "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" -ValueName "EveryoneIncludesAnonymous" -Type DWord -Value 0
                    
                    # User Rights Assignment for Tier 0
                    $userRightsConfig = @"
[Unicode]
Unicode=yes
[System Access]
MinimumPasswordAge = 1
MaximumPasswordAge = 60
MinimumPasswordLength = 14
PasswordComplexity = 1
PasswordHistorySize = 24
LockoutBadCount = 5
LockoutDuration = 30
RequireLogonToChangePassword = 0
ForceLogoffWhenHourExpire = 0
ClearTextPassword = 0
LSAAnonymousNameLookup = 0
[Privilege Rights]
SeDenyLogonAsServiceRight = Guests
SeDenyRemoteInteractiveLogonRight = Guests
SeAllowLogonLocallyRight = Administrators,Backup Operators
SeRemoteInteractiveLogonRight = Administrators
[Event Audit]
AuditSystemEvents = 3
AuditLogonEvents = 3
AuditObjectAccess = 1
AuditPrivilegeUse = 3
AuditPolicyChange = 3
AuditAccountManage = 3
AuditProcessTracking = 1
AuditDSAccess = 3
AuditAccountLogon = 3
"@
                    
                } elseif ($tierLevel -eq "Tier1") {
                    Write-Verbose "Applying Tier 1 specific settings..."
                    
                    # Device Guard
                    if ($enableDevGuard) {
                        Set-GPRegistryValue -Name $gpoName -Key "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" -ValueName "ConfigureSystemGuardLaunch" -Type DWord -Value 1
                        Set-GPRegistryValue -Name $gpoName -Key "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" -ValueName "EnableVirtualizationBasedSecurity" -Type DWord -Value 1
                    }
                    
                    # Server-specific hardening
                    Set-GPRegistryValue -Name $gpoName -Key "HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" -ValueName "NodeType" -Type DWord -Value 2
                    Set-GPRegistryValue -Name $gpoName -Key "HKLM\SOFTWARE\Microsoft\.NETFramework\v4.0.30319" -ValueName "SchUseStrongCrypto" -Type DWord -Value 1
                    Set-GPRegistryValue -Name $gpoName -Key "HKLM\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319" -ValueName "SchUseStrongCrypto" -Type DWord -Value 1
                    
                    # User Rights Assignment for Tier 1
                    $userRightsConfig = @"
[Unicode]
Unicode=yes
[System Access]
MinimumPasswordAge = 1
MaximumPasswordAge = 60
MinimumPasswordLength = 12
PasswordComplexity = 1
PasswordHistorySize = 12
LockoutBadCount = 5
LockoutDuration = 30
RequireLogonToChangePassword = 0
ForceLogoffWhenHourExpire = 0
ClearTextPassword = 0
LSAAnonymousNameLookup = 0
[Privilege Rights]
SeDenyLogonAsServiceRight = Guests
SeDenyRemoteInteractiveLogonRight = Guests
SeAllowLogonLocallyRight = Administrators,Backup Operators,Users
SeRemoteInteractiveLogonRight = Administrators,Remote Desktop Users
[Event Audit]
AuditSystemEvents = 3
AuditLogonEvents = 3
AuditObjectAccess = 1
AuditPrivilegeUse = 3
AuditPolicyChange = 3
AuditAccountManage = 3
AuditProcessTracking = 1
AuditDSAccess = 1
AuditAccountLogon = 3
"@
                }
                
                # Apply security template
                $securityTemplatePath = "$env:TEMP\EAM-$tierLevel-Security.inf"
                $userRightsConfig | Out-File -FilePath $securityTemplatePath -Encoding Unicode
                
                # Import security template into GPO
                try {
                    $result = & secedit.exe /configure /cfg $securityTemplatePath /db "$env:TEMP\EAM-$tierLevel.sdb" /areas SECURITYPOLICY /quiet
                    if ($LASTEXITCODE -eq 0) {
                        Write-Verbose "Security template imported successfully"
                    }
                } catch {
                    Write-Warning "Failed to import security template: $_"
                }
                
                # Link GPO to target OU
                Write-Verbose "Linking GPO to OU: $targetOU"
                try {
                    New-GPLink -Name $gpoName -Target $targetOU -LinkEnabled Yes -Enforced Yes
                    Write-Verbose "GPO linked successfully"
                } catch {
                    Write-Warning "Failed to link GPO: $_"
                }
                
                # Create WMI filter for tier-specific targeting (optional)
                $wmiFilterName = "EAM-$tierLevel-Filter"
                $wmiQuery = if ($tierLevel -eq "Tier0") { 
                    "SELECT * FROM Win32_ComputerSystem WHERE DomainRole = 4 OR DomainRole = 5" 
                } else { 
                    "SELECT * FROM Win32_ComputerSystem WHERE DomainRole = 2 OR DomainRole = 3" 
                }
                
                try {
                    $wmiFilter = New-GPWmiFilter -Name $wmiFilterName -Expression $wmiQuery -Description "Filter for $tierLevel systems"
                    $gpo.WmiFilter = $wmiFilter
                    Write-Verbose "WMI filter created and applied"
                } catch {
                    Write-Warning "Failed to create WMI filter: $_"
                }
                
                # Backup the GPO
                try {
                    $backupPath = $using:GPOBackupPath
                    Backup-GPO -Name $gpoName -Path $backupPath
                    Write-Verbose "GPO backed up to $backupPath"
                } catch {
                    Write-Warning "Failed to backup GPO: $_"
                }
                
                Write-Verbose "GPO creation and configuration completed successfully"
            }
            
            DependsOn = @("[WindowsFeature]GPMCFeature", "[WindowsFeature]RSATADPowerShell")
        }
        
        # Script to create additional GPOs for Windows Firewall rules
        Script CreateFirewallGPO {
            GetScript = {
                $gpoName = "EAM-$using:TierLevel-Firewall-Policy"
                try {
                    $gpo = Get-GPO -Name $gpoName -ErrorAction Stop
                    return @{
                        Result = "Firewall GPO exists: $($gpo.DisplayName)"
                        GPOExists = $true
                    }
                } catch {
                    return @{
                        Result = "Firewall GPO does not exist"
                        GPOExists = $false
                    }
                }
            }
            
            TestScript = {
                $gpoName = "EAM-$using:TierLevel-Firewall-Policy"
                try {
                    $gpo = Get-GPO -Name $gpoName -ErrorAction Stop
                    return ($gpo -ne $null)
                } catch {
                    return $false
                }
            }
            
            SetScript = {
                Import-Module GroupPolicy
                
                $gpoName = "EAM-$using:TierLevel-Firewall-Policy"
                $domain = $using:DomainName
                $targetOU = $using:TargetOU
                $tierLevel = $using:TierLevel
                
                # Create the Firewall GPO
                Write-Verbose "Creating Firewall GPO: $gpoName"
                $gpo = New-GPO -Name $gpoName -Domain $domain -Comment "Enterprise Access Model $tierLevel firewall rules"
                
                # Enable Windows Firewall for all profiles
                Set-GPRegistryValue -Name $gpoName -Key "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" -ValueName "EnableFirewall" -Type DWord -Value 1
                Set-GPRegistryValue -Name $gpoName -Key "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile" -ValueName "EnableFirewall" -Type DWord -Value 1
                Set-GPRegistryValue -Name $gpoName -Key "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" -ValueName "EnableFirewall" -Type DWord -Value 1
                
                # Configure default actions
                Set-GPRegistryValue -Name $gpoName -Key "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" -ValueName "DefaultInboundAction" -Type DWord -Value 1
                Set-GPRegistryValue -Name $gpoName -Key "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" -ValueName "DefaultOutboundAction" -Type DWord -Value 0
                
                if ($tierLevel -eq "Tier0") {
                    # Tier 0 specific firewall rules - more restrictive
                    Set-GPRegistryValue -Name $gpoName -Key "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" -ValueName "DisableNotifications" -Type DWord -Value 1
                    Set-GPRegistryValue -Name $gpoName -Key "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" -ValueName "LogFilePath" -Type String -Value "%SystemRoot%\System32\LogFiles\Firewall\pfirewall.log"
                    Set-GPRegistryValue -Name $gpoName -Key "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" -ValueName "LogFileSize" -Type DWord -Value 32767
                    Set-GPRegistryValue -Name $gpoName -Key "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" -ValueName "LogDroppedPackets" -Type DWord -Value 1
                    Set-GPRegistryValue -Name $gpoName -Key "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" -ValueName "LogSuccessfulConnections" -Type DWord -Value 1
                } elseif ($tierLevel -eq "Tier1") {
                    # Tier 1 specific firewall rules
                    Set-GPRegistryValue -Name $gpoName -Key "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" -ValueName "DisableNotifications" -Type DWord -Value 0
                    Set-GPRegistryValue -Name $gpoName -Key "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" -ValueName "LogFilePath" -Type String -Value "%SystemRoot%\System32\LogFiles\Firewall\pfirewall.log"
                    Set-GPRegistryValue -Name $gpoName -Key "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" -ValueName "LogFileSize" -Type DWord -Value 16384
                    Set-GPRegistryValue -Name $gpoName -Key "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" -ValueName "LogDroppedPackets" -Type DWord -Value 1
                }
                
                # Link Firewall GPO to target OU
                Write-Verbose "Linking Firewall GPO to OU: $targetOU"
                try {
                    New-GPLink -Name $gpoName -Target $targetOU -LinkEnabled Yes -Order 2
                    Write-Verbose "Firewall GPO linked successfully"
                } catch {
                    Write-Warning "Failed to link Firewall GPO: $_"
                }
            }
            
            DependsOn = @("[Script]CreateEnterpriseAccessModelGPO")
        }
        
        # Script to force Group Policy update on target computers
        Script ForceGPUpdate {
            GetScript = {
                return @{
                    Result = "Group Policy update status"
                }
            }
            
            TestScript = {
                # Always return false to force GPO refresh
                return $false
            }
            
            SetScript = {
                $targetOU = $using:TargetOU
                
                # Get computers from target OU
                try {
                    $computers = Get-ADComputer -SearchBase $targetOU -Filter * | Select-Object -ExpandProperty Name
                    
                    foreach ($computer in $computers) {
                        if (Test-Connection -ComputerName $computer -Count 1 -Quiet) {
                            Write-Verbose "Forcing GP update on $computer"
                            try {
                                Invoke-Command -ComputerName $computer -ScriptBlock {
                                    gpupdate /force /target:computer
                                } -ErrorAction SilentlyContinue
                            } catch {
                                Write-Warning "Failed to update GP on $computer : $_"
                            }
                        }
                    }
                } catch {
                    Write-Warning "Failed to get computers from OU: $_"
                }
            }
            
            DependsOn = @("[Script]CreateEnterpriseAccessModelGPO", "[Script]CreateFirewallGPO")
        }
    }
}