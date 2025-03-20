#################################################################################################################
#
#
#
#           Windows Server 2019 Hardening Script according to its DISA STIG (PowerShell Version)
#
#
#
#
#################################################################################################################
# Credits and More info: https://gist.github.com/mackwage/08604751462126599d7e52f233490efe
#                        https://github.com/LOLBAS-Project/LOLBAS
#                        https://lolbas-project.github.io/
#                        https://github.com/Disassembler0/Win10-Initial-Setup-Script
#                        https://github.com/cryps1s/DARKSURGEON/tree/master/configuration/configuration-scripts
#                        https://gist.github.com/alirobe/7f3b34ad89a159e6daa1#file-reclaimwindows10-ps1-L71
#                        https://github.com/teusink/Home-Security-by-W10-Hardening
#                        https://gist.github.com/ricardojba/ecdfe30dadbdab6c514a530bc5d51ef6
#
#################################################################################################################
# Change file associations to protect against common ransomware attacks
# Note that if you legitimately use these extensions, like .bat, you will now need to execute them manually from cmd or powershell
# Alternatively, you can right-click on them and hit 'Run as Administrator' but ensure it's a script you want to run :)
# ---------------------
# Changing back example (x64):
# ftype htafile=C:\Windows\SysWOW64\mshta.exe "%1" {1E460BD7-F1C3-4B2E-88BF-4E770A288AF5}%U{1E460BD7-F1C3-4B2E-88BF-4E770A288AF5} %*

# Function to change file associations
function Set-FileAssociation {
    param (
        [string]$Extension,
        [string]$FileType
    )
    
    cmd /c "assoc $Extension=$FileType"
}

# Set file associations to txtfile to protect against common attack vectors
$extensionsToProtect = @(
    ".bat", ".cmd", ".chm", ".hta", ".jse", ".js", ".vbe", ".vbs", 
    ".wsc", ".wsf", ".ws", ".wsh", ".sct", ".url", ".ps1", ".reg", 
    ".wcx", ".slk", ".iqy", ".prn", ".diff", ".rdg", ".application", ".deploy"
)

foreach ($ext in $extensionsToProtect) {
    Set-FileAssociation -Extension $ext -FileType "txtfile"
}

# https://posts.specterops.io/the-tale-of-settingcontent-ms-files-f1ea253e4d39
Remove-ItemProperty -Path "HKCR:\SettingContent\Shell\Open\Command" -Name "DelegateExecute" -Force -ErrorAction SilentlyContinue
New-ItemProperty -Path "HKCR:\SettingContent\Shell\Open\Command" -Name "DelegateExecute" -Value "" -PropertyType String -Force

# https://posts.specterops.io/remote-code-execution-via-path-traversal-in-the-device-metadata-authoring-wizard-a0d5839fc54f
Remove-Item -Path "HKLM:\SOFTWARE\Classes\.devicemetadata-ms" -Force -ErrorAction SilentlyContinue
Remove-Item -Path "HKLM:\SOFTWARE\Classes\.devicemanifest-ms" -Force -ErrorAction SilentlyContinue

#################################################################################################################
# Workaround for CoronaBlue/SMBGhost Worm exploiting CVE-2020-0796
# https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/ADV200005
# Disable SMBv3 compression
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" DisableCompression -Type DWORD -Value 1 -Force

#################################################################################################################
# Windows Defender Device Guard - Exploit Guard Policies (Windows 10 Only)
# Enable ASR rules in Win10 ExploitGuard (>= 1709) to mitigate Office malspam
# Blocks Office childprocs, Office proc injection, Office win32 api calls & executable content creation
# Note these only work when Defender is your primary AV

# Enable Windows Defender sandboxing
[Environment]::SetEnvironmentVariable("MP_FORCE_USE_SANDBOX", "1", "Machine")

# Update signatures
Start-Process -FilePath "$env:ProgramFiles\Windows Defender\MpCmdRun.exe" -ArgumentList "-SignatureUpdate" -Wait

# Enable Defender signatures for Potentially Unwanted Applications (PUA)
Set-MpPreference -PUAProtection Enabled

# Enable Defender periodic scanning
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows Defender" -Name "PassiveMode" -Value 2 -PropertyType DWord -Force

# Enable early launch antimalware driver for scan of boot-start drivers
# 3 is the default which allows good, unknown and 'bad but critical'. Recommend trying 1 for 'good and unknown' or 8 which is 'good only'
New-ItemProperty -Path "HKCU:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch" -Name "DriverLoadPolicy" -Value 3 -PropertyType DWord -Force

# Stop some of the most common SMB based lateral movement techniques dead in their tracks
Set-MpPreference -AttackSurfaceReductionRules_Ids D1E49AAC-8F56-4280-B9BA-993A6D -AttackSurfaceReductionRules_Actions Enabled

# Block Office applications from creating child processes
Add-MpPreference -AttackSurfaceReductionRules_Ids D4F940AB-401B-4EFC-AADC-AD5F3C50688A -AttackSurfaceReductionRules_Actions Enabled

# Block Office applications from injecting code into other processes
Add-MpPreference -AttackSurfaceReductionRules_Ids 75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84 -AttackSurfaceReductionRules_Actions Enabled

# Block Win32 API calls from Office macro
Add-MpPreference -AttackSurfaceReductionRules_Ids 92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B -AttackSurfaceReductionRules_Actions Enabled

# Block Office applications from creating executable content
Add-MpPreference -AttackSurfaceReductionRules_Ids 3B576869-A4EC-4529-8536-B80A7769E899 -AttackSurfaceReductionRules_Actions Enabled

# Block execution of potentially obfuscated scripts
Add-MpPreference -AttackSurfaceReductionRules_Ids 5BEB7EFE-FD9A-4556-801D-275E5FFC04CC -AttackSurfaceReductionRules_Actions Enabled

# Block executable content from email client and webmail
Add-MpPreference -AttackSurfaceReductionRules_Ids BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550 -AttackSurfaceReductionRules_Actions Enabled

# Block JavaScript or VBScript from launching downloaded executable content
Add-MpPreference -AttackSurfaceReductionRules_Ids D3E037E1-3EB8-44C8-A917-57927947596D -AttackSurfaceReductionRules_Actions Enabled

# Block executable files from running unless they meet a prevalence, age, or trusted list criteria
Add-MpPreference -AttackSurfaceReductionRules_Ids 01443614-cd74-433a-b99e-2ecdc07bfc25 -AttackSurfaceReductionRules_Actions Enabled

# Use advanced protection against ransomware
Add-MpPreference -AttackSurfaceReductionRules_Ids C1DB55AB-C21A-4637-BB3F-A12568109D35 -AttackSurfaceReductionRules_Actions Enabled

# Block Win32 API calls from Office macro
Add-MpPreference -AttackSurfaceReductionRules_Ids 92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B -AttackSurfaceReductionRules_Actions Enabled

# Block credential stealing from the Windows local security authority subsystem (lsass.exe)
Add-MpPreference -AttackSurfaceReductionRules_Ids 9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2 -AttackSurfaceReductionRules_Actions Enabled

# Block untrusted and unsigned processes that run from USB
Add-MpPreference -AttackSurfaceReductionRules_Ids B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4 -AttackSurfaceReductionRules_Actions Enabled

# Enable Controlled Folder
Set-MpPreference -EnableControlledFolderAccess Enabled

# Enable Cloud functionality of Windows Defender
Set-MpPreference -MAPSReporting Advanced
Set-MpPreference -SubmitSamplesConsent SendAllSamples

# Enable Defender exploit system-wide protection
# The commented line includes CFG which can cause issues with apps like Discord & Mouse Without Borders
Set-Processmitigation -System -Enable DEP,EmulateAtlThunks,BottomUp,HighEntropy,SEHOP,SEHOPTelemetry,TerminateOnError

# Enable Network protection
Set-MpPreference -EnableNetworkProtection Enabled

#################################################################################################################
# Enable exploit protection (EMET on Windows 10)
Invoke-WebRequest -Uri https://demo.wd.microsoft.com/Content/ProcessMitigation.xml -OutFile ProcessMitigation.xml
Set-ProcessMitigation -PolicyFilePath ProcessMitigation.xml
Remove-Item ProcessMitigation.xml

#################################################################################################################
# General OS hardening
# Disable DNS Multicast, NTLM, SMBv1, NetBIOS over TCP/IP, PowerShellV2, AutoRun, 8.3 names, Last Access timestamp and weak TLS/SSL ciphers and protocols
# Enables UAC, SMB/LDAP Signing, Show hidden files

# Disable storing password in memory in cleartext
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential" -Value 0 -PropertyType DWord -Force

# Prevent Kerberos from using DES or RC4
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" -Name "SupportedEncryptionTypes" -Value 2147483640 -PropertyType DWord -Force

# DNS and TCP/IP hardening
$registryPaths = @{
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" = @{
        "EnableMulticast" = 1
        "DisableSmartNameResolution" = 1
    }
    "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" = @{
        "DisableParallelAandAAAA" = 1
    }
    "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" = @{
        "IGMPLevel" = 0
        "DisableIPSourceRouting" = 2
        "EnableICMPRedirect" = 0
    }
    "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" = @{
        "DisableIPSourceRouting" = 2
    }
}

foreach ($path in $registryPaths.Keys) {
    if (!(Test-Path $path)) {
        New-Item -Path $path -Force | Out-Null
    }
    
    foreach ($name in $registryPaths[$path].Keys) {
        New-ItemProperty -Path $path -Name $name -Value $registryPaths[$path][$name] -PropertyType DWord -Force
    }
}

# SMB and security hardening
$securitySettings = @{
    "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" = @{
        "SMB1" = 0
        "RestrictNullSessAccess" = 1
    }
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" = @{
        "EnableLUA" = 1
        "EnableVirtualization" = 1
        "ConsentPromptBehaviorAdmin" = 2
    }
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" = @{
        "SaveZoneInformation" = 2
    }
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" = @{
        "NoDataExecutionPrevention" = 0
        "NoHeapTerminationOnCorruption" = 0
    }
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers" = @{
        "DisableWebPnPDownload" = 1
        "DisableHTTPPrinting" = 1
    }
    "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" = @{
        "AutoConnectAllowedOEM" = 0
    }
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" = @{
        "fMinimizeConnections" = 1
    }
    "HKLM:\SYSTEM\CurrentControlSet\Services\Netbt\Parameters" = @{
        "NoNameReleaseOnDemand" = 1
    }
}

foreach ($path in $securitySettings.Keys) {
    if (!(Test-Path $path)) {
        New-Item -Path $path -Force | Out-Null
    }
    
    foreach ($name in $securitySettings[$path].Keys) {
        New-ItemProperty -Path $path -Name $name -Value $securitySettings[$path][$name] -PropertyType DWord -Force
    }
}

# LSA Security Settings
$lsaSettings = @{
    "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" = @{
        "NTLMMinServerSec" = 537395200
        "NTLMMinClientSec" = 537395200
        "allownullsessionfallback" = 0
    }
    "HKLM:\System\CurrentControlSet\Control\Lsa" = @{
        "LMCompatibilityLevel" = 5
        "RestrictAnonymousSAM" = 1
        "RestrictAnonymous" = 1
        "EveryoneIncludesAnonymous" = 0
        "UseMachineId" = 1
        "LimitBlankPasswordUse" = 1
    }
}

foreach ($path in $lsaSettings.Keys) {
    if (!(Test-Path $path)) {
        New-Item -Path $path -Force | Out-Null
    }
    
    foreach ($name in $lsaSettings[$path].Keys) {
        if ($name -eq "RestrictRemoteSAM") {
            # Special handling for string value
            New-ItemProperty -Path $path -Name $name -Value "O:BAG:BAD:(A;;RC;;;BA)" -PropertyType String -Force
        } else {
            New-ItemProperty -Path $path -Name $name -Value $lsaSettings[$path][$name] -PropertyType DWord -Force
        }
    }
}

# Force logoff if smart card removed - Set to "2" for logoff, set to "1" for lock
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "SCRemoveOption" -Value 2 -PropertyType DWord -Force

# WPAD Mitigation
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad" -Name "WpadOverride" -Value 1 -PropertyType DWord -Force

# Enable SMB/LDAP Signing
$signingSettings = @{
    "HKLM:\System\CurrentControlSet\Services\LanmanWorkStation\Parameters" = @{
        "RequireSecuritySignature" = 1
        "EnableSecuritySignature" = 1
    }
    "HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters" = @{
        "RequireSecuritySignature" = 1
        "EnableSecuritySignature" = 1
    }
    "HKLM:\System\CurrentControlSet\Services\NTDS\Parameters" = @{
        "LDAPServerIntegrity" = 2
    }
    "HKLM:\System\CurrentControlSet\Services\ldap" = @{
        "LDAPClientIntegrity " = 1
    }
}

foreach ($path in $signingSettings.Keys) {
    if (!(Test-Path $path)) {
        New-Item -Path $path -Force | Out-Null
    }
    
    foreach ($name in $signingSettings[$path].Keys) {
        New-ItemProperty -Path $path -Name $name -Value $signingSettings[$path][$name] -PropertyType DWord -Force
    }
}

# Domain member settings
$domainSettings = @{
    "HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters" = @{
        "RequireSignOrSeal" = 1
        "SealSecureChannel" = 1
        "SignSecureChannel" = 1
    }
}

foreach ($path in $domainSettings.Keys) {
    if (!(Test-Path $path)) {
        New-Item -Path $path -Force | Out-Null
    }
    
    foreach ($name in $domainSettings[$path].Keys) {
        New-ItemProperty -Path $path -Name $name -Value $domainSettings[$path][$name] -PropertyType DWord -Force
    }
}

# Enable SmartScreen
$smartScreenSettings = @{
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" = @{
        "EnableSmartScreen" = 1
    }
}

foreach ($path in $smartScreenSettings.Keys) {
    if (!(Test-Path $path)) {
        New-Item -Path $path -Force | Out-Null
    }
    
    foreach ($name in $smartScreenSettings[$path].Keys) {
        if ($name -eq "ShellSmartScreenLevel") {
            # String value
            New-ItemProperty -Path $path -Name $name -Value "Block" -PropertyType String -Force
        } else {
            New-ItemProperty -Path $path -Name $name -Value $smartScreenSettings[$path][$name] -PropertyType DWord -Force
        }
    }
}

# Prevent (remote) DLL Hijacking
$dllHijackingSettings = @{
    "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" = @{
        "CWDIllegalInDllSearch" = 0x2
        "SafeDLLSearchMode" = 1
        "ProtectionMode" = 1
    }
}

foreach ($path in $dllHijackingSettings.Keys) {
    if (!(Test-Path $path)) {
        New-Item -Path $path -Force | Out-Null
    }
    
    foreach ($name in $dllHijackingSettings[$path].Keys) {
        New-ItemProperty -Path $path -Name $name -Value $dllHijackingSettings[$path][$name] -PropertyType DWord -Force
    }
}

# Disable (c|w)script.exe to prevent the system from running VBS scripts
$scriptHostSettings = @{
    "HKCU:\SOFTWARE\Microsoft\Windows Script Host\Settings" = @{
        "Enabled" = 0
    }
}

foreach ($path in $scriptHostSettings.Keys) {
    if (!(Test-Path $path)) {
        New-Item -Path $path -Force | Out-Null
    }
    
    foreach ($name in $scriptHostSettings[$path].Keys) {
        New-ItemProperty -Path $path -Name $name -Value $scriptHostSettings[$path][$name] -PropertyType DWord -Force
    }
}

# Additional script host settings (string values)
$scriptHostStrings = @{
    "HKCU:\SOFTWARE\Microsoft\Windows Script Host\Settings" = @{
        "ActiveDebugging" = "1"
        "DisplayLogo" = "1"
        "SilentTerminate" = "0"
        "UseWINSAFER" = "1"
    }
}

foreach ($path in $scriptHostStrings.Keys) {
    if (!(Test-Path $path)) {
        New-Item -Path $path -Force | Out-Null
    }
    
    foreach ($name in $scriptHostStrings[$path].Keys) {
        New-ItemProperty -Path $path -Name $name -Value $scriptHostStrings[$path][$name] -PropertyType String -Force
    }
}

# Disable IPv6
# https://support.microsoft.com/en-us/help/929852/guidance-for-configuring-ipv6-in-windows-for-advanced-users
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\tcpip6\parameters" -Name "DisabledComponents" -Value 0xFF -PropertyType DWord -Force

# Windows Remote Access Settings
# Disable solicited remote assistance
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fAllowToGetHelp" -Value 0 -PropertyType DWord -Force
# Require encrypted RPC connections to Remote Desktop
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fEncryptRPCTraffic" -Value 1 -PropertyType DWord -Force

# Removal Media Settings
# Disable autorun/autoplay on all drives
$autoRunSettings = @{
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" = @{
        "NoAutoplayfornonVolume" = 1
    }
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer" = @{
        "NoDriveTypeAutoRun" = 255
    }
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" = @{
        "NoAutorun" = 1
    }
}

foreach ($path in $autoRunSettings.Keys) {
    if (!(Test-Path $path)) {
        New-Item -Path $path -Force | Out-Null
    }
    
    foreach ($name in $autoRunSettings[$path].Keys) {
        New-ItemProperty -Path $path -Name $name -Value $autoRunSettings[$path][$name] -PropertyType DWord -Force
    }
}

# Stop and configure WinRM
Stop-Service -Name WinRM
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" -Name "AllowUnencryptedTraffic" -Value 0 -PropertyType DWord -Force
# Disable WinRM Client Digest authentication
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" -Name "AllowDigest" -Value 0 -PropertyType DWord -Force
Start-Service -Name WinRM

# Disabling RPC usage from a remote asset interacting with scheduled tasks
New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Schedule" -Name "DisableRpcOverTcp" -Value 1 -PropertyType DWord -Force
# Disabling RPC usage from a remote asset interacting with services
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control" -Name "DisableRemoteScmEndpoints" -Value 1 -PropertyType DWord -Force

# Stop NetBIOS over TCP/IP
# Using WMI to set TcpipNetbiosOptions to 2 (Disable NetBIOS over TCP/IP)
Get-WmiObject -Class Win32_NetworkAdapterConfiguration | Where-Object { $_.TcpipNetbiosOptions -eq 0 -or $_.TcpipNetbiosOptions -eq 1 } | ForEach-Object { $_.SetTcpipNetbios(2) }

# Disable SMBv1
Disable-WindowsOptionalFeature -Online -FeatureName smb1protocol
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10" -Name "Start" -Value 4 -PropertyType DWord -Force

# Disable Powershellv2 (uncomment if needed)
# Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2
# Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root

#################################################################################################################
# Harden lsass to help protect against credential dumping (Mimikatz)
# Configures lsass.exe as a protected process and disables wdigest
# Enables delegation of non-exported credentials which enables support for Restricted Admin Mode or Remote Credential Guard
$lsassHardeningSettings = @{
    "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe" = @{
        "AuditLevel" = 0x8
    }
    "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" = @{
        "RunAsPPL" = 1
        "DisableRestrictedAdmin" = 0
        "DisableRestrictedAdminOutboundCreds" = 1
    }
    "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" = @{
        "UseLogonCredential" = 0
        "Negotiate" = 0
    }
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation" = @{
        "AllowProtectedCreds" = 1
    }
}

foreach ($path in $lsassHardeningSettings.Keys) {
    if (!(Test-Path $path)) {
        New-Item -Path $path -Force | Out-Null
    }
    
    foreach ($name in $lsassHardeningSettings[$path].Keys) {
        New-ItemProperty -Path $path -Name $name -Value $lsassHardeningSettings[$path][$name] -PropertyType DWord -Force
    }
}

#################################################################################################################
# Disable the ClickOnce trust prompt
# This only partially mitigates the risk of malicious ClickOnce Apps - the ability to run the manifest is disabled, but hash retrieval is still possible
$clickOnceSettings = @{
    "HKLM:\SOFTWARE\MICROSOFT\.NETFramework\Security\TrustManager\PromptingLevel" = @{
        "MyComputer" = "Disabled"
        "LocalIntranet" = "Disabled"
        "Internet" = "Disabled"
        "TrustedSites" = "Disabled"
        "UntrustedSites" = "Disabled"
    }
}

foreach ($path in $clickOnceSettings.Keys) {
    if (!(Test-Path $path)) {
        New-Item -Path $path -Force | Out-Null
    }
    
    foreach ($name in $clickOnceSettings[$path].Keys) {
        New-ItemProperty -Path $path -Name $name -Value $clickOnceSettings[$path][$name] -PropertyType String -Force
    }
}

#################################################################################################################
# Enable Windows Firewall and configure some advanced options
# Block Win32/64 binaries (LOLBins) from making net connections when they shouldn't
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True

# Helper function to create firewall block rules
function New-LolbinsFirewallRule {
    param (
        [string]$RuleName,
        [string]$ProgramPath
    )
    
    if (Test-Path $ProgramPath) {
        New-NetFirewallRule -DisplayName $RuleName -Direction Outbound -Program $ProgramPath -Protocol TCP -Action Block -Enabled True -Profile Any | Out-Null
    }
}

# System32 binaries
$system32Path = "$env:SystemRoot\system32"
$lolbinsSys32 = @(
    "calc.exe", "certutil.exe", "cmstp.exe", "cscript.exe", "esentutl.exe", 
    "expand.exe", "extrac32.exe", "findstr.exe", "hh.exe", "makecab.exe", 
    "mshta.exe", "msiexec.exe", "nltest.exe", "notepad.exe", "pcalua.exe", 
    "print.exe", "regsvr32.exe", "replace.exe", "rundll32.exe", "runscripthelper.exe", 
    "scriptrunner.exe", "SyncAppvPublishingServer.exe", "regasm.exe", "odbcconf.exe"
)

foreach ($lolbin in $lolbinsSys32) {
    New-LolbinsFirewallRule -RuleName "Block $lolbin netconns" -ProgramPath "$system32Path\$lolbin"
}

# Special case for wmic
New-LolbinsFirewallRule -RuleName "Block wmic.exe netconns" -ProgramPath "$system32Path\wbem\wmic.exe"

# SysWOW64 binaries
$sysWow64Path = "$env:SystemRoot\SysWOW64"
$lolbinsSysWow64 = @(
    "calc.exe", "certutil.exe", "cmstp.exe", "cscript.exe", "esentutl.exe", 
    "expand.exe", "extrac32.exe", "findstr.exe", "hh.exe", "makecab.exe", 
    "mshta.exe", "msiexec.exe", "nltest.exe", "notepad.exe", "pcalua.exe", 
    "print.exe", "regsvr32.exe", "replace.exe", "rpcping.exe", "rundll32.exe", 
    "runscripthelper.exe", "scriptrunner.exe", "SyncAppvPublishingServer.exe", 
    "regasm.exe", "odbcconf.exe"
)

foreach ($lolbin in $lolbinsSysWow64) {
    New-LolbinsFirewallRule -RuleName "Block $lolbin netconns" -ProgramPath "$sysWow64Path\$lolbin"
}

# Special case for wmic in SysWOW64
New-LolbinsFirewallRule -RuleName "Block wmic.exe netconns" -ProgramPath "$sysWow64Path\wbem\wmic.exe"

# Special cases for Office applications
New-LolbinsFirewallRule -RuleName "Block appvlp.exe netconns" -ProgramPath "C:\Program Files (x86)\Microsoft Office\root\client\AppVLP.exe"
New-LolbinsFirewallRule -RuleName "Block appvlp.exe netconns" -ProgramPath "C:\Program Files\Microsoft Office\root\client\AppVLP.exe"

# Special case for wscript.exe
New-LolbinsFirewallRule -RuleName "Block wscript.exe netconns" -ProgramPath "$system32Path\wscript.exe"
New-LolbinsFirewallRule -RuleName "Block wscript.exe netconns" -ProgramPath "$sysWow64Path\wscript.exe"

# Disable TCP timestamps
netsh int tcp set global timestamps=disabled

# Enable Firewall Logging
netsh advfirewall set currentprofile logging filename "$env:SystemRoot\system32\LogFiles\Firewall\pfirewall.log"
netsh advfirewall set currentprofile logging maxfilesize 4096
netsh advfirewall set currentprofile logging droppedconnections enable

# Block all inbound connections on Public profile - enable this only when you are sure you have physical access.
# This will disable RDP and Share and all other inbound connections to this computer.
# Uncomment the next line to enable, and the line after it to disable the setting
# netsh advfirewall set publicprofile firewallpolicy blockinboundalways,allowoutbound
# netsh advfirewall set publicprofile firewallpolicy notconfigured,notconfigured

#################################################################################################################
# Show known file extensions and hidden files
$explorerSettings = @{
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" = @{
        "HideFileExt" = 0
        "Hidden" = 1
        "ShowSuperHidden" = 1
    }
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" = @{
        "HideFileExt" = 0
        "Hidden" = 1
        "ShowSuperHidden" = 1
    }
}

foreach ($path in $explorerSettings.Keys) {
    if (!(Test-Path $path)) {
        New-Item -Path $path -Force | Out-Null
    }
    
    foreach ($name in $explorerSettings[$path].Keys) {
        New-ItemProperty -Path $path -Name $name -Value $explorerSettings[$path][$name] -PropertyType DWord -Force
    }
}

# Disable 8.3 names (Mitigate Microsoft IIS tilde directory enumeration) and Last Access timestamp for files and folder (Performance)
fsutil behavior set disable8dot3 1
fsutil behavior set disablelastaccess 0

#################################################################################################################
# Biometrics
# Enable anti-spoofing for facial recognition
$biometricSettings = @{
    "HKLM:\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures" = @{
        "EnhancedAntiSpoofing" = 1
    }
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" = @{
        "NoLockScreenCamera" = 1
    }
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" = @{
        "LetAppsActivateWithVoiceAboveLock" = 2
        "LetAppsActivateWithVoice" = 2
    }
}

foreach ($path in $biometricSettings.Keys) {
    if (!(Test-Path $path)) {
        New-Item -Path $path -Force | Out-Null
    }
    
    foreach ($name in $biometricSettings[$path].Keys) {
        New-ItemProperty -Path $path -Name $name -Value $biometricSettings[$path][$name] -PropertyType DWord -Force
    }
}

#################################################################################################################
# Disable weak TLS/SSL ciphers and protocols
# Cipher configuration

# Helper function to set registry keys for TLS/SSL settings
function Set-TlsSslCipherSetting {
    param (
        [string]$Path,
        [string]$Name,
        [object]$Value,
        [string]$Type = "DWORD"
    )
    
    if (!(Test-Path $Path)) {
        New-Item -Path $Path -Force | Out-Null
    }
    
    if ($Type -eq "DWORD") {
        New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType DWord -Force | Out-Null
    } else {
        New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType String -Force | Out-Null
    }
}

# Encryption - Ciphers: AES only - IISCrypto (recommended options)
$cipherSettings = @{
    "AES 128/128" = 0xffffffff
    "AES 256/256" = 0xffffffff
    "DES 56/56" = 0
    "NULL" = 0
    "RC2 128/128" = 0
    "RC2 40/128" = 0
    "RC2 56/128" = 0
    "RC4 128/128" = 0
    "RC4 40/128" = 0
    "RC4 56/128" = 0
    "RC4 64/128" = 0
    "Triple DES 168" = 0
}

foreach ($cipher in $cipherSettings.Keys) {
    $path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\$cipher"
    Set-TlsSslCipherSetting -Path $path -Name "Enabled" -Value $cipherSettings[$cipher]
}

# Encryption - Hashes: All allowed - IISCrypto (recommended options)
$hashSettings = @{
    "MD5" = 0xffffffff
    "SHA" = 0xffffffff
    "SHA256" = 0xffffffff
    "SHA384" = 0xffffffff
    "SHA512" = 0xffffffff
}

foreach ($hash in $hashSettings.Keys) {
    $path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\$hash"
    Set-TlsSslCipherSetting -Path $path -Name "Enabled" -Value $hashSettings[$hash]
}

# Encryption - Key Exchanges: All allowed
Set-TlsSslCipherSetting -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman" -Name "Enabled" -Value 0xffffffff
Set-TlsSslCipherSetting -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman" -Name "ServerMinKeyBitLength" -Value 0x00001000
Set-TlsSslCipherSetting -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\ECDH" -Name "Enabled" -Value 0xffffffff
Set-TlsSslCipherSetting -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\PKCS" -Name "Enabled" -Value 0xffffffff

# Encryption - Protocols configuration
$protocols = @(
    "Multi-Protocol Unified Hello",
    "PCT 1.0",
    "SSL 2.0",
    "SSL 3.0",
    "TLS 1.0",
    "TLS 1.1",
    "TLS 1.2"
)

$protocolSettings = @{
    "Multi-Protocol Unified Hello" = @{
        "Client" = @{ "Enabled" = 0; "DisabledByDefault" = 1 }
        "Server" = @{ "Enabled" = 0; "DisabledByDefault" = 1 }
    }
    "PCT 1.0" = @{
        "Client" = @{ "Enabled" = 0; "DisabledByDefault" = 1 }
        "Server" = @{ "Enabled" = 0; "DisabledByDefault" = 1 }
    }
    "SSL 2.0" = @{
        "Client" = @{ "Enabled" = 0; "DisabledByDefault" = 1 }
        "Server" = @{ "Enabled" = 0; "DisabledByDefault" = 1 }
    }
    "SSL 3.0" = @{
        "Client" = @{ "Enabled" = 0; "DisabledByDefault" = 1 }
        "Server" = @{ "Enabled" = 0; "DisabledByDefault" = 1 }
    }
    "TLS 1.0" = @{
        "Client" = @{ "Enabled" = 0xffffffff; "DisabledByDefault" = 0 }
        "Server" = @{ "Enabled" = 0xffffffff; "DisabledByDefault" = 0 }
    }
    "TLS 1.1" = @{
        "Client" = @{ "Enabled" = 0xffffffff; "DisabledByDefault" = 0 }
        "Server" = @{ "Enabled" = 0xffffffff; "DisabledByDefault" = 0 }
    }
    "TLS 1.2" = @{
        "Client" = @{ "Enabled" = 0xffffffff; "DisabledByDefault" = 0 }
        "Server" = @{ "Enabled" = 0xffffffff; "DisabledByDefault" = 0 }
    }
}

foreach ($protocol in $protocols) {
    foreach ($clientServer in @("Client", "Server")) {
        $path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$protocol\$clientServer"
        
        if ($protocolSettings.ContainsKey($protocol) -and $protocolSettings[$protocol].ContainsKey($clientServer)) {
            foreach ($setting in $protocolSettings[$protocol][$clientServer].Keys) {
                Set-TlsSslCipherSetting -Path $path -Name $setting -Value $protocolSettings[$protocol][$clientServer][$setting]
            }
        }
    }
}

# Encryption - Cipher Suites (order) - All cipher included to avoid application problems
$cipherOrder = "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,TLS_RSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_128_GCM_SHA256,TLS_RSA_WITH_AES_256_CBC_SHA256,TLS_RSA_WITH_AES_128_CBC_SHA256,TLS_RSA_WITH_AES_256_CBC_SHA,TLS_RSA_WITH_AES_128_CBC_SHA,TLS_AES_256_GCM_SHA384,TLS_AES_128_GCM_SHA256,TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,TLS_RSA_WITH_3DES_EDE_CBC_SHA,TLS_RSA_WITH_NULL_SHA256,TLS_RSA_WITH_NULL_SHA,TLS_PSK_WITH_AES_256_GCM_SHA384,TLS_PSK_WITH_AES_128_GCM_SHA256,TLS_PSK_WITH_AES_256_CBC_SHA384,TLS_PSK_WITH_AES_128_CBC_SHA256,TLS_PSK_WITH_NULL_SHA384,TLS_PSK_WITH_NULL_SHA256"
Set-TlsSslCipherSetting -Path "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002" -Name "Functions" -Value $cipherOrder -Type "String"

# OCSP stapling - Enabling this registry key has a potential performance impact
# Set-TlsSslCipherSetting -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL" -Name "EnableOcspStaplingForSni" -Value 1

# Enabling Strong Authentication for .NET Framework 3.5
Set-TlsSslCipherSetting -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727" -Name "SchUseStrongCrypto" -Value 1
Set-TlsSslCipherSetting -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727" -Name "SystemDefaultTlsVersions" -Value 1
Set-TlsSslCipherSetting -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727" -Name "SchUseStrongCrypto" -Value 1
Set-TlsSslCipherSetting -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727" -Name "SystemDefaultTlsVersions" -Value 1

# Enabling Strong Authentication for .NET Framework 4.0/4.5.x
Set-TlsSslCipherSetting -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319" -Name "SchUseStrongCrypto" -Value 1
Set-TlsSslCipherSetting -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319" -Name "SystemDefaultTlsVersions" -Value 1

#################################################################################################################
# Enable and Configure Internet Browser Settings
#################################################################################################################

# Enable SmartScreen for Edge
if (!(Test-Path "HKCU:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter")) {
    New-Item -Path "HKCU:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" -Force | Out-Null
}
New-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" -Name "EnabledV9" -Value 1 -PropertyType DWord -Force

# Enable Notifications in IE when a site attempts to install software
if (!(Test-Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer")) {
    New-Item -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Force | Out-Null
}
New-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name "SafeForScripting" -Value 0 -PropertyType DWord -Force

# Disable Edge password manager to encourage use of proper password manager
if (!(Test-Path "HKCU:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main")) {
    New-Item -Path "HKCU:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" -Force | Out-Null
}
New-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" -Name "FormSuggest Passwords" -Value "no" -PropertyType String -Force

#################################################################################################################
# Enable Advanced Windows Logging
#################################################################################################################

# Enlarge Windows Event Security Log Size
wevtutil sl Security /ms:1024000
wevtutil sl Application /ms:1024000
wevtutil sl System /ms:1024000
wevtutil sl "Windows Powershell" /ms:1024000
wevtutil sl "Microsoft-Windows-PowerShell/Operational" /ms:1024000

# Record command line data in process creation events eventid 4688
if (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit")) {
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Force | Out-Null
}
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -PropertyType DWord -Force

# Enabled Advanced Settings
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "SCENoApplyLegacyAuditPolicy" -Value 1 -PropertyType DWord -Force

# Enable PowerShell Logging
if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Force | Out-Null
}
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Name "EnableModuleLogging" -Value 1 -PropertyType DWord -Force

if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Force | Out-Null
}
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1 -PropertyType DWord -Force

# Enable Windows Event Detailed Logging
# This is intentionally meant to be a subset of expected enterprise logging as this script may be used on consumer devices.
$auditCategories = @(
    @{Category = "Security Group Management"; Success = $true; Failure = $true},
    @{Category = "Process Creation"; Success = $true; Failure = $true},
    @{Category = "Logoff"; Success = $true; Failure = $false},
    @{Category = "Logon"; Success = $true; Failure = $true},
    @{Category = "Removable Storage"; Success = $true; Failure = $true},
    @{Category = "SAM"; Success = $false; Failure = $false},
    @{Category = "Filtering Platform Policy Change"; Success = $false; Failure = $false},
    @{Category = "Security State Change"; Success = $true; Failure = $true},
    @{Category = "Security System Extension"; Success = $true; Failure = $true},
    @{Category = "System Integrity"; Success = $true; Failure = $true}
)

foreach ($category in $auditCategories) {
    $successValue = if ($category.Success) { "enable" } else { "disable" }
    $failureValue = if ($category.Failure) { "enable" } else { "disable" }
    
    & auditpol.exe /set /subcategory:"$($category.Category)" /success:$successValue /failure:$failureValue
}

Write-Output "Windows Server 2019 hardening script has completed successfully."