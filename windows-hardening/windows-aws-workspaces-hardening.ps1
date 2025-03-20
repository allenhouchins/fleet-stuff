#################################################################
#
# Windows 10 Security Hardening PowerShell Script
# Converted from Atlant Security's Windows 10 Hardening Script
# https://atlantsecurity.com
#
#################################################################

# Create a system restore point before hardening
Write-Host "Creating a system restore point before applying security hardening..." -ForegroundColor Green
Enable-ComputerRestore -Drive "C:\"
vssadmin resize shadowstorage /on=c: /for=c: /maxsize=500MB
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" -Name "SystemRestorePointCreationFrequency" -Value 20 -Type DWord
Checkpoint-Computer -Description "BeforeSecurityHardening" -RestorePointType "MODIFY_SETTINGS"

# Block tools which remotely install services
Write-Host "Blocking remote service installation..." -ForegroundColor Green
Set-ItemProperty -Path "HKLM:\Software\Microsoft\OLE" -Name "EnableDCOM" -Value "N" -Type String

# Change file associations to protect against common ransomware and social engineering attacks
Write-Host "Changing file associations to protect against common attacks..." -ForegroundColor Green
$dangerousExtensions = @(
    ".bat", ".cmd", ".chm", ".hta", ".jse", ".js", ".vbe", ".vbs", 
    ".wsc", ".wsf", ".ws", ".wsh", ".sct", ".url", ".ps1", ".iso", 
    ".reg", ".wcx", ".slk", ".iqy", ".prn", ".diff", ".rdg", ".deploy"
)

foreach ($ext in $dangerousExtensions) {
    cmd /c "assoc $ext=txtfile"
}

# Remove dangerous file type associations
Remove-Item -Path "HKLM:\SOFTWARE\Classes\.devicemetadata-ms" -Force -ErrorAction SilentlyContinue
Remove-Item -Path "HKLM:\SOFTWARE\Classes\.devicemanifest-ms" -Force -ErrorAction SilentlyContinue

# Workaround for CoronaBlue/SMBGhost Worm exploiting CVE-2020-0796
Write-Host "Applying CVE-2020-0796 mitigation..." -ForegroundColor Green
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "DisableCompression" -Type DWORD -Value 1 -Force

#################################################################
# Windows Defender Exploit Guard Policies
#################################################################
Write-Host "Configuring Windows Defender Exploit Guard policies..." -ForegroundColor Green

# Enable Windows Defender sandboxing
[Environment]::SetEnvironmentVariable("MP_FORCE_USE_SANDBOX", "1", "Machine")

# Update signatures
& "$env:ProgramFiles\Windows Defender\MpCmdRun.exe" -SignatureUpdate

# Enable Defender signatures for PUA
Set-MpPreference -PUAProtection Enabled

# Enable Defender periodic scanning
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows Defender" -Name "PassiveMode" -Value 2 -Type DWord

# Enable early launch antimalware driver
Set-ItemProperty -Path "HKCU:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch" -Name "DriverLoadPolicy" -Value 3 -Type DWord

# Configure Attack Surface Reduction rules
$asrRules = @{
    # Stop SMB-based lateral movement
    'D1E49AAC-8F56-4280-B9BA-993A6D' = 'Enabled'
    # Block Office applications from creating child processes
    'D4F940AB-401B-4EFC-AADC-AD5F3C50688A' = 'Enabled'
    # Block Office applications from injecting code into other processes
    '75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84' = 'Enabled'
    # Block Win32 API calls from Office macro
    '92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B' = 'Enabled'
    # Block Office applications from creating executable content
    '3B576869-A4EC-4529-8536-B80A7769E899' = 'Enabled'
    # Block execution of potentially obfuscated scripts
    '5BEB7EFE-FD9A-4556-801D-275E5FFC04CC' = 'Enabled'
    # Block executable content from email client and webmail
    'BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550' = 'Enabled'
    # Block JavaScript or VBScript from launching downloaded executable content
    'D3E037E1-3EB8-44C8-A917-57927947596D' = 'Enabled'
    # Block executable files from running unless they meet a prevalence, age, or trusted list criteria
    '01443614-cd74-433a-b99e-2ecdc07bfc25' = 'Enabled'
    # Use advanced protection against ransomware
    'C1DB55AB-C21A-4637-BB3F-A12568109D35' = 'Enabled'
    # Block credential stealing from the Windows local security authority subsystem
    '9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2' = 'Enabled'
    # Block untrusted and unsigned processes that run from USB
    'B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4' = 'Enabled'
}

foreach ($rule in $asrRules.GetEnumerator()) {
    Add-MpPreference -AttackSurfaceReductionRules_Ids $rule.Key -AttackSurfaceReductionRules_Actions $rule.Value
}

# Enable Controlled Folder Access
Set-MpPreference -EnableControlledFolderAccess Enabled

# Enable Cloud functionality of Windows Defender
Set-MpPreference -MAPSReporting Advanced
Set-MpPreference -SubmitSamplesConsent SendAllSamples

# Enable Defender exploit system-wide protection
Set-ProcessMitigation -System -Enable DEP,EmulateAtlThunks,BottomUp,HighEntropy,SEHOP,SEHOPTelemetry,TerminateOnError

# Enable Network protection
Set-MpPreference -EnableNetworkProtection Enabled

# Enable exploit protection
Write-Host "Configuring exploit protection..." -ForegroundColor Green
$processXmlUrl = "https://demo.wd.microsoft.com/Content/ProcessMitigation.xml"
$processXmlPath = "$env:TEMP\ProcessMitigation.xml"

Invoke-WebRequest -Uri $processXmlUrl -OutFile $processXmlPath
Set-ProcessMitigation -PolicyFilePath $processXmlPath
Remove-Item $processXmlPath -Force

#################################################################
# MS Office hardening against common malspam attacks
#################################################################
Write-Host "Hardening Microsoft Office settings..." -ForegroundColor Green

$officeVersions = @("12.0", "14.0", "15.0", "16.0")
$officeApps = @("Word", "Excel", "PowerPoint", "Publisher", "Outlook")

foreach ($version in $officeVersions) {
    # VBA warnings for Word and Publisher
    if ($version -in @("12.0", "14.0", "15.0", "16.0")) {
        Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Office\$version\Word\Security" -Name "vbawarnings" -Value 4 -Type DWord -Force -ErrorAction SilentlyContinue
        Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Office\$version\Publisher\Security" -Name "vbawarnings" -Value 4 -Type DWord -Force -ErrorAction SilentlyContinue
    }
    
    # Office 15.0 and 16.0 specific settings
    if ($version -in @("15.0", "16.0")) {
        Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Office\$version\Outlook\Security" -Name "markinternalasunsafe" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
        
        foreach ($app in @("Word", "Excel", "PowerPoint")) {
            Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Office\$version\$app\Security" -Name "blockcontentexecutionfrominternet" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
        }
    }
}

# Configure Word to not update links automatically
foreach ($version in @("14.0", "15.0", "16.0")) {
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Office\$version\Word\Options" -Name "DontUpdateLinks" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Office\$version\Word\Options\WordMail" -Name "DontUpdateLinks" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
}

#################################################################
# General OS hardening
#################################################################
Write-Host "Applying general OS hardening settings..." -ForegroundColor Green

# Disable storing password in memory in cleartext
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential" -Value 0 -Type DWord

# Prevent Kerberos from using DES or RC4
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" -Name "SupportedEncryptionTypes" -Value 2147483640 -Type DWord

# DNS Settings
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "DisableSmartNameResolution" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" -Name "DisableParallelAandAAAA" -Value 1 -Type DWord

# TCP/IP Protection
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "DisableIPSourceRouting" -Value 2 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "EnableICMPRedirect" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" -Name "DisableIPSourceRouting" -Value 2 -Type DWord

# Disable SMBv1
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "SMB1" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" -Name "RestrictNullSessAccess" -Value 1 -Type DWord

# UAC settings
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableVirtualization" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 2 -Type DWord

# Other security settings
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" -Name "SaveZoneInformation" -Value 2 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoDataExecutionPrevention" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoHeapTerminationOnCorruption" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Name "AutoConnectAllowedOEM" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" -Name "fMinimizeConnections" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netbt\Parameters" -Name "NoNameReleaseOnDemand" -Value 1 -Type DWord

# NTLM Security settings
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -Name "NTLMMinServerSec" -Value 537395200 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -Name "NTLMMinClientSec" -Value 537395200 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\LSA\MSV1_0" -Name "allownullsessionfallback" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "LMCompatibilityLevel" -Value 5 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymousSAM" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymous" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "EveryoneIncludesAnonymous" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictRemoteSAM" -Value "O:BAG:BAD:(A;;RC;;;BA)" -Type String
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "UseMachineId" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LimitBlankPasswordUse" -Value 1 -Type DWord

# WPAD Protection
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad" -Name "WpadOverride" -Value 1 -Type DWord

# Force logoff if smart card removed
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "SCRemoveOption" -Value 2 -Type DWord

# Enable SMB/LDAP Signing
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanmanWorkStation\Parameters" -Name "RequireSecuritySignature" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanmanWorkStation\Parameters" -Name "EnableSecuritySignature" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters" -Name "RequireSecuritySignature" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters" -Name "EnableSecuritySignature" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\NTDS\Parameters" -Name "LDAPServerIntegrity" -Value 2 -Type DWord
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\ldap" -Name "LDAPClientIntegrity" -Value 1 -Type DWord

# Secure Channel settings
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters" -Name "RequireSignOrSeal" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters" -Name "SealSecureChannel" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters" -Name "SignSecureChannel" -Value 1 -Type DWord

# Enable SmartScreen
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableSmartScreen" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "ShellSmartScreenLevel" -Value "Block" -Type String

# Prevent DLL Hijacking
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name "CWDIllegalInDllSearch" -Value 0x2 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name "SafeDLLSearchMode" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name "ProtectionMode" -Value 1 -Type DWord

# Disable script execution
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows Script Host\Settings" -Name "Enabled" -Value 0 -Type DWord
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows Script Host\Settings" -Name "ActiveDebugging" -Value 1 -Type String
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows Script Host\Settings" -Name "DisplayLogo" -Value 1 -Type String
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows Script Host\Settings" -Name "SilentTerminate" -Value 0 -Type String
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows Script Host\Settings" -Name "UseWINSAFER" -Value 1 -Type String

# Disable IPv6
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\tcpip6\parameters" -Name "DisabledComponents" -Value 0xFF -Type DWord

# Remote Access Settings
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fAllowToGetHelp" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fEncryptRPCTraffic" -Value 1 -Type DWord

# Disable autorun/autoplay on all drives
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoAutoplayfornonVolume" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer" -Name "NoDriveTypeAutoRun" -Value 255 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoAutorun" -Value 1 -Type DWord

# Stop and configure WinRM
Stop-Service -Name WinRM -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" -Name "AllowUnencryptedTraffic" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" -Name "AllowDigest" -Value 0 -Type DWord
Start-Service -Name WinRM

# Disable RPC remote access
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Schedule" -Name "DisableRpcOverTcp" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control" -Name "DisableRemoteScmEndpoints" -Value 1 -Type DWord

#################################################################
# Harden LSASS to protect against credential dumping
#################################################################
Write-Host "Hardening LSASS against credential dumping..." -ForegroundColor Green

Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe" -Name "AuditLevel" -Value 8 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "DisableRestrictedAdmin" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "DisableRestrictedAdminOutboundCreds" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "Negotiate" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation" -Name "AllowProtectedCreds" -Value 1 -Type DWord

#################################################################
# Windows Firewall Configuration
#################################################################
Write-Host "Configuring Windows Firewall..." -ForegroundColor Green

# Enable Windows Firewall
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True

# Define known LOLBins (Living Off The Land Binaries) to block network connections
$lolBins = @(
    "$env:ProgramFiles (x86)\Microsoft Office\root\client\AppVLP.exe",
    "$env:ProgramFiles\Microsoft Office\root\client\AppVLP.exe",
    "$env:SystemRoot\system32\calc.exe",
    "$env:SystemRoot\SysWOW64\calc.exe",
    "$env:SystemRoot\system32\certutil.exe",
    "$env:SystemRoot\SysWOW64\certutil.exe",
    "$env:SystemRoot\system32\cmstp.exe",
    "$env:SystemRoot\SysWOW64\cmstp.exe",
    "$env:SystemRoot\system32\cscript.exe",
    "$env:SystemRoot\SysWOW64\cscript.exe",
    "$env:SystemRoot\system32\esentutl.exe",
    "$env:SystemRoot\SysWOW64\esentutl.exe",
    "$env:SystemRoot\system32\expand.exe",
    "$env:SystemRoot\SysWOW64\expand.exe",
    "$env:SystemRoot\system32\extrac32.exe",
    "$env:SystemRoot\SysWOW64\extrac32.exe",
    "$env:SystemRoot\system32\findstr.exe",
    "$env:SystemRoot\SysWOW64\findstr.exe",
    "$env:SystemRoot\system32\hh.exe",
    "$env:SystemRoot\SysWOW64\hh.exe",
    "$env:SystemRoot\system32\makecab.exe",
    "$env:SystemRoot\SysWOW64\makecab.exe",
    "$env:SystemRoot\system32\mshta.exe",
    "$env:SystemRoot\SysWOW64\mshta.exe",
    "$env:SystemRoot\system32\msiexec.exe",
    "$env:SystemRoot\SysWOW64\msiexec.exe",
    "$env:SystemRoot\system32\nltest.exe",
    "$env:SystemRoot\SysWOW64\nltest.exe",
    "$env:SystemRoot\system32\notepad.exe",
    "$env:SystemRoot\SysWOW64\notepad.exe",
    "$env:SystemRoot\system32\odbcconf.exe",
    "$env:SystemRoot\SysWOW64\odbcconf.exe",
    "$env:SystemRoot\system32\pcalua.exe",
    "$env:SystemRoot\SysWOW64\pcalua.exe",
    "$env:SystemRoot\system32\regasm.exe",
    "$env:SystemRoot\SysWOW64\regasm.exe",
    "$env:SystemRoot\system32\regsvr32.exe",
    "$env:SystemRoot\SysWOW64\regsvr32.exe",
    "$env:SystemRoot\system32\replace.exe",
    "$env:SystemRoot\SysWOW64\replace.exe",
    "$env:SystemRoot\SysWOW64\rpcping.exe",
    "$env:SystemRoot\system32\rundll32.exe",
    "$env:SystemRoot\SysWOW64\rundll32.exe",
    "$env:SystemRoot\system32\runscripthelper.exe",
    "$env:SystemRoot\SysWOW64\runscripthelper.exe",
    "$env:SystemRoot\system32\scriptrunner.exe",
    "$env:SystemRoot\SysWOW64\scriptrunner.exe",
    "$env:SystemRoot\system32\SyncAppvPublishingServer.exe",
    "$env:SystemRoot\SysWOW64\SyncAppvPublishingServer.exe",
    "$env:SystemRoot\system32\wbem\wmic.exe",
    "$env:SystemRoot\SysWOW64\wbem\wmic.exe",
    "$env:SystemRoot\system32\wscript.exe",
    "$env:SystemRoot\SysWOW64\wscript.exe"
)

foreach ($bin in $lolBins) {
    $binName = Split-Path $bin -Leaf
    New-NetFirewallRule -DisplayName "Block $binName network connections" -Direction Outbound -Program $bin -Protocol TCP -Action Block -Profile Any -ErrorAction SilentlyContinue
}

# Enable Firewall Logging
Set-NetFirewallProfile -All -LogFileName "$env:SystemRoot\system32\LogFiles\Firewall\pfirewall.log" -LogMaxSizeKilobytes 4096 -LogBlocked True -LogAllowed False

#################################################################
# Disable AutoRun and Show File Extensions
#################################################################
Write-Host "Disabling AutoRun and showing file extensions..." -ForegroundColor Green

# Disable AutoRun
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Value 0xff -Type DWord
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Value 0xff -Type DWord

# Show known file extensions and hidden files
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Value 0 -Type DWord
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -Value 1 -Type DWord
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowSuperHidden" -Value 1 -Type DWord
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowSuperHidden" -Value 1 -Type DWord

# Disable 8.3 names and Last Access timestamp
fsutil behavior set disable8dot3 1
fsutil behavior set disablelastaccess 0

#################################################################
# Edge Browser Security Settings
#################################################################
Write-Host "Configuring Edge browser security settings..." -ForegroundColor Green

# Set Edge security settings
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" -Name "EnabledV9" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name "SafeForScripting" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" -Name "FormSuggest Passwords" -Value "no" -Type String -Force -ErrorAction SilentlyContinue

# Create Edge policy paths if they don't exist
$edgePolicyPaths = @(
    "HKLM:\Software\Policies\Microsoft\Edge"
)

foreach ($path in $edgePolicyPaths) {
    if (-not (Test-Path $path)) {
        New-Item -Path $path -Force | Out-Null
    }
}

# Configure Edge security settings
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Edge" -Name "SitePerProcess" -Value 1 -Type DWord -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Edge" -Name "SSLVersionMin" -Value "tls1.2^@" -Type String -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Edge" -Name "NativeMessagingUserLevelHosts" -Value 0 -Type DWord -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Edge" -Name "SmartScreenEnabled" -Value 1 -Type DWord -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Edge" -Name "PreventSmartScreenPromptOverride" -Value 1 -Type DWord -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Edge" -Name "PreventSmartScreenPromptOverrideForFiles" -Value 1 -Type DWord -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Edge" -Name "SSLErrorOverrideAllowed" -Value 0 -Type DWord -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Edge" -Name "SmartScreenPuaEnabled" -Value 1 -Type DWord -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Edge" -Name "AllowDeletingBrowserHistory" -Value 0 -Type DWord -Force

# Create Edge extension policy paths
$edgeExtensionPaths = @(
    "HKLM:\Software\Policies\Microsoft\Edge\ExtensionInstallAllowlist",
    "HKLM:\Software\Policies\Microsoft\Edge\ExtensionInstallForcelist",
    "HKLM:\Software\Wow6432Node\Microsoft\Edge\Extensions\odfafepnkmbhccpbejgmiehpchacaeak"
)

foreach ($path in $edgeExtensionPaths) {
    if (-not (Test-Path $path)) {
        New-Item -Path $path -Force | Out-Null
    }
}

# Add Edge security extensions
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Edge\ExtensionInstallAllowlist" -Name "1" -Value "odfafepnkmbhccpbejgmiehpchacaeak" -Type String -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Edge\ExtensionInstallForcelist" -Name "1" -Value "odfafepnkmbhccpbejgmiehpchacaeak" -Type String -Force
Set-ItemProperty -Path "HKLM:\Software\Wow6432Node\Microsoft\Edge\Extensions\odfafepnkmbhccpbejgmiehpchacaeak" -Name "update_url" -Value "https://edge.microsoft.com/extensionwebstorebase/v1/crx" -Type String -Force

#################################################################
# Configure Google Chrome Security Settings
#################################################################
Write-Host "Configuring Chrome browser security settings..." -ForegroundColor Green

# Create Chrome policy paths if they don't exist
$chromePolicyPaths = @(
    "HKLM:\SOFTWARE\Policies\Google\Chrome",
    "HKLM:\SOFTWARE\Policies\Google\Chrome\ExtensionInstallWhitelist",
    "HKLM:\SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist",
    "HKLM:\SOFTWARE\Policies\Google\Chrome\URLBlacklist",
    "HKLM:\SOFTWARE\Policies\Google\Chrome\Recommended",
    "HKLM:\SOFTWARE\Policies\Google\Update"
)

foreach ($path in $chromePolicyPaths) {
    if (-not (Test-Path $path)) {
        New-Item -Path $path -Force | Out-Null
    }
}

# Basic Chrome Security Settings
$chromeSettings = @{
    "AllowCrossOriginAuthPrompt" = 0
    "AlwaysOpenPdfExternally" = 0
    "AmbientAuthenticationInPrivateModesEnabled" = 0
    "AudioCaptureAllowed" = 1
    "AudioSandboxEnabled" = 1
    "DnsOverHttpsMode" = "on"
    "ScreenCaptureAllowed" = 1
    "SitePerProcess" = 1
    "TLS13HardeningForLocalAnchorsEnabled" = 1
    "VideoCaptureAllowed" = 1
}

foreach ($setting in $chromeSettings.GetEnumerator()) {
    if ($setting.Value -is [int]) {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name $setting.Key -Value $setting.Value -Type DWord -Force
    } else {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name $setting.Key -Value $setting.Value -Type String -Force
    }
}

# Advanced Chrome Security Settings
$advancedChromeSettings = @{
    "AdvancedProtectionAllowed" = 1
    "RemoteAccessHostFirewallTraversal" = 0
    "DefaultPopupsSetting" = 33554432
    "DefaultGeolocationSetting" = 33554432
    "AllowOutdatedPlugins" = 0
    "BackgroundModeEnabled" = 0
    "CloudPrintProxyEnabled" = 0
    "MetricsReportingEnabled" = 0
    "SearchSuggestEnabled" = 0
    "ImportSavedPasswords" = 0
    "IncognitoModeAvailability" = 16777216
    "EnableOnlineRevocationChecks" = 16777216
    "SavingBrowserHistoryDisabled" = 0
    "DefaultPluginsSetting" = 50331648
    "AllowDeletingBrowserHistory" = 0
    "PromptForDownloadLocation" = 16777216
    "DownloadRestrictions" = 33554432
    "AutoplayAllowed" = 0
    "SafeBrowsingExtendedReportingEnabled" = 0
    "DefaultWebUsbGuardSetting" = 33554432
    "ChromeCleanupEnabled" = 0
    "ChromeCleanupReportingEnabled" = 0
    "EnableMediaRouter" = 0
    "UrlKeyedAnonymizedDataCollectionEnabled" = 0
    "WebRtcEventLogCollectionAllowed" = 0
    "NetworkPredictionOptions" = 33554432
    "BrowserGuestModeEnabled" = 0
    "ImportAutofillFormData" = 0
}

foreach ($setting in $advancedChromeSettings.GetEnumerator()) {
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name $setting.Key -Value $setting.Value -Type DWord -Force
}

# Set SSLVersionMin policy
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name "SSLVersionMin" -Value "tls1.1" -Type String -Force

# Add uBlock Origin to whitelist and forcelist
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome\ExtensionInstallWhitelist" -Name "1" -Value "cjpalhdlnbpafiamejdnhcphjbkeiagm" -Type String -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist" -Name "1" -Value "cjpalhdlnbpafiamejdnhcphjbkeiagm" -Type String -Force

# Block javascript: URLs
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome\URLBlacklist" -Name "1" -Value "javascript://*" -Type String -Force

# Set update check period
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Update" -Name "AutoUpdateCheckPeriodMinutes" -Value 1613168640 -Type DWord -Force

# Set recommended Safe Browsing level
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome\Recommended" -Name "SafeBrowsingProtectionLevel" -Value 2 -Type DWord -Force

#################################################################
# Adobe Reader DC Security Hardening
#################################################################
Write-Host "Configuring Adobe Reader DC security settings..." -ForegroundColor Green

# Create Adobe Reader policy paths if they don't exist
$adobePolicyPaths = @(
    "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cCloud",
    "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cDefaultLaunchURLPerms",
    "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cServices",
    "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cSharePoint",
    "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cWebmailProfiles",
    "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cWelcomeScreen",
    "HKLM:\Software\Adobe\Acrobat Reader\DC\Installer",
    "HKLM:\Software\Wow6432Node\Adobe\Acrobat Reader\DC\Installer"
)

foreach ($path in $adobePolicyPaths) {
    if (-not (Test-Path $path)) {
        New-Item -Path $path -Force | Out-Null
    }
}

# Configure Adobe Reader base settings
Set-ItemProperty -Path "HKLM:\Software\Adobe\Acrobat Reader\DC\Installer" -Name "DisableMaintenance" -Value 1 -Type DWord -Force
Set-ItemProperty -Path "HKLM:\Software\Wow6432Node\Adobe\Acrobat Reader\DC\Installer" -Name "DisableMaintenance" -Value 1 -Type DWord -Force

# Configure Adobe Reader feature lock down settings
$adobeFeatureLockdown = @{
    "bAcroSuppressUpsell" = 1
    "bDisablePDFHandlerSwitching" = 1
    "bDisableTrustedFolders" = 1
    "bDisableTrustedSites" = 1
    "bEnableFlash" = 0
    "bEnhancedSecurityInBrowser" = 1
    "bEnhancedSecurityStandalone" = 1
    "bProtectedMode" = 1
    "iFileAttachmentPerms" = 1
    "iProtectedView" = 2
}

foreach ($setting in $adobeFeatureLockdown.GetEnumerator()) {
    Set-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" -Name $setting.Key -Value $setting.Value -Type DWord -Force
}

# Configure Adobe Reader cloud settings
Set-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cCloud" -Name "bAdobeSendPluginToggle" -Value 1 -Type DWord -Force

# Configure Adobe Reader URL permissions
Set-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cDefaultLaunchURLPerms" -Name "iURLPerms" -Value 3 -Type DWord -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cDefaultLaunchURLPerms" -Name "iUnknownURLPerms" -Value 2 -Type DWord -Force

# Configure Adobe Reader services settings
$adobeServicesSettings = @{
    "bToggleAdobeDocumentServices" = 1
    "bToggleAdobeSign" = 1
    "bTogglePrefsSync" = 1
    "bToggleWebConnectors" = 1
    "bUpdater" = 0
}

foreach ($setting in $adobeServicesSettings.GetEnumerator()) {
    Set-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cServices" -Name $setting.Key -Value $setting.Value -Type DWord -Force
}

# Configure additional Adobe Reader settings
Set-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cSharePoint" -Name "bDisableSharePointFeatures" -Value 1 -Type DWord -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cWebmailProfiles" -Name "bDisableWebmail" -Value 1 -Type DWord -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cWelcomeScreen" -Name "bShowWelcomeScreen" -Value 0 -Type DWord -Force

#################################################################
# Enhanced Windows Event Logging
#################################################################
Write-Host "Configuring enhanced Windows event logging..." -ForegroundColor Green

# Enlarge Windows Event Security Log Size
wevtutil sl Security /ms:1024000
wevtutil sl Application /ms:1024000
wevtutil sl System /ms:1024000
wevtutil sl "Windows Powershell" /ms:1024000
wevtutil sl "Microsoft-Windows-PowerShell/Operational" /ms:1024000

# Record command line data in process creation events eventid 4688
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -Type DWord -Force

# Enable Advanced Settings
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "SCENoApplyLegacyAuditPolicy" -Value 1 -Type DWord -Force

# Enable PowerShell Logging
if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Force | Out-Null
}
if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Force | Out-Null
}

Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Name "EnableModuleLogging" -Value 1 -Type DWord -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1 -Type DWord -Force

# Configure Windows Event Detailed Logging
$auditingSettings = @{
    "Security Group Management" = @("enable", "enable")  # Success, Failure
    "Process Creation" = @("enable", "enable")
    "Logoff" = @("enable", "disable")
    "Logon" = @("enable", "enable")
    "Removable Storage" = @("enable", "enable")
    "SAM" = @("disable", "disable")
    "Filtering Platform Policy Change" = @("disable", "disable")
    "Security State Change" = @("enable", "enable")
    "Security System Extension" = @("enable", "enable")
    "System Integrity" = @("enable", "enable")
}

foreach ($setting in $auditingSettings.GetEnumerator()) {
    Auditpol /set /subcategory:"$($setting.Key)" /success:$($setting.Value[0]) /failure:$($setting.Value[1])
}

Write-Host "Windows AWS security hardening has been completed successfully." -ForegroundColor Green
Write-Host "It's recommended to restart your computer to apply all changes." -ForegroundColor Yellow