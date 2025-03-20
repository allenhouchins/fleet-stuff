#######################################################################################################################
#
#    Atlant Security (https://atlantsecurity.com)'s Windows 10 Security Hardening Script - 
#    Includes Microsoft 365, Office, Chrome, Adobe Reader, Edge security settings. 
#    Read the comments and uncomment or comment relevant sections to make best use of it. 
#    License: Free to use for personal use. For commercial use, contact Atlant security at https://atlantsecurity.com/
#
#######################################################################################################################
# Credits and More info: https://gist.github.com/mackwage/08604751462126599d7e52f233490efe
#                        https://github.com/LOLBAS-Project/LOLBAS
#                        https://lolbas-project.github.io/
#                        https://github.com/Disassembler0/Win10-Initial-Setup-Script
#                        https://github.com/cryps1s/DARKSURGEON/tree/master/configuration/configuration-scripts
#                        https://gist.github.com/alirobe/7f3b34ad89a159e6daa1#file-reclaimwindows10-ps1-L71
#                        https://github.com/teusink/Home-Security-by-W10-Hardening
#                        https://gist.github.com/ricardojba/ecdfe30dadbdab6c514a530bc5d51ef6
#
#######################################################################################################################
#######################################################################################################################
# INSTRUCTIONS
# Find the "EDIT" lines and change them according to your requirements and organization. Some lines
# are not appropriate for large companies using Active Directory infrastructure, others are fine for small organizations, 
# others are fine for individual users. At the start of tricky lines, I've added guidelines. 
# It is a good idea to create a System Restore point before you run the script - as there is a lot of code,
# finding out which line broke your machine is going to be tricky. You can also run the script in sequences manually the 
# first few times, reboot, test your software and connectivity, proceed with the next sequence - this helps with troubleshooting.
# HOW TO RUN THE SCRIPT
# The command below creates the restore point, you can do it manually, too. 

# Make sure we're running as administrator
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "This script needs to be run as an administrator. Please restart it with admin privileges."
    exit
}

# Create a system restore point
Enable-ComputerRestore -Drive "C:\"
Resize-VolumeCheckpoint -Drive "C:" -MaxSize 5GB
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" -Name "SystemRestorePointCreationFrequency" -Value 20 -Type DWord
Checkpoint-Computer -Description "BeforeSecurityHardening" -RestorePointType "MODIFY_SETTINGS"

# Block tools which remotely install services, such as psexec!
# EDIT: Run the command below manually! It does not work in a script.
# $sdSet = sc.exe sdshow scmanager
# if ($sdSet) {
#     $newSD = $sdSet -replace ":", ""
#     sc.exe sdset scmanager D:(D;;GA;;;NU)$newSD
# }

# Block remote commands
Set-ItemProperty -Path "HKLM:\Software\Microsoft\OLE" -Name "EnableDCOM" -Value "N" -Type String

# Change file associations to protect against common ransomware and social engineering attacks
# These are for regular users. Technically savvy users know how to mount an ISO or run a script even if they are associated with notepad.
$fileAssociations = @(
    ".bat", ".cmd", ".chm", ".hta", ".jse", ".js", ".vbe", ".vbs", ".wsc", ".wsf", ".ws", ".wsh",
    ".scr", ".url", ".ps1", ".iso", ".reg", ".wcx", ".slk", ".iqy", ".prn", ".diff", ".rdg", ".deploy"
)

foreach ($ext in $fileAssociations) {
    cmd /c "assoc $ext=txtfile"
}

# https://posts.specterops.io/the-tale-of-settingcontent-ms-files-f1ea253e4d39
# Mitigate .devicemetadata-ms and .devicemanifest-ms vulnerabilities
Remove-Item -Path "HKLM:\SOFTWARE\Classes\.devicemetadata-ms" -Force -ErrorAction SilentlyContinue
Remove-Item -Path "HKLM:\SOFTWARE\Classes\.devicemanifest-ms" -Force -ErrorAction SilentlyContinue

# Prevent Local windows wireless exploitation: the Airstrike attack
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "DontDisplayNetworkSelectionUI" -Value 1 -Type DWord

# Workaround for CoronaBlue/SMBGhost Worm exploiting CVE-2020-0796
# Disable SMBv3 compression
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "DisableCompression" -Value 1 -Type DWord

#######################################################################################################################
# Windows Defender Device Guard - Exploit Guard Policies (Windows 10 Only)
# Enable ASR rules in Win10 ExploitGuard (>= 1709) to mitigate Office malspam
# Blocks Office childprocs, Office proc injection, Office win32 api calls & executable content creation
# Note these only work when Defender is your primary AV

# Enable Windows Defender sandboxing
[Environment]::SetEnvironmentVariable("MP_FORCE_USE_SANDBOX", "1", "Machine")

# Update signatures
& "$env:ProgramFiles\Windows Defender\MpCmdRun.exe" -SignatureUpdate

# Enable Defender signatures for Potentially Unwanted Applications (PUA)
Set-MpPreference -PUAProtection Enabled

# Enable Defender periodic scanning
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows Defender" -Name "PassiveMode" -Value 2 -Type DWord

# Enable early launch antimalware driver for scan of boot-start drivers
# 3 is the default which allows good, unknown and 'bad but critical'. Recommend trying 1 for 'good and unknown' or 8 which is 'good only'
Set-ItemProperty -Path "HKCU:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch" -Name "DriverLoadPolicy" -Value 3 -Type DWord

# Stop some of the most common SMB based lateral movement techniques dead in their tracks
Set-MpPreference -AttackSurfaceReductionRules_Ids "D1E49AAC-8F56-4280-B9BA-993A6D" -AttackSurfaceReductionRules_Actions Enabled

# Block Office applications from creating child processes
Add-MpPreference -AttackSurfaceReductionRules_Ids "D4F940AB-401B-4EFC-AADC-AD5F3C50688A" -AttackSurfaceReductionRules_Actions Enabled

# Block Office applications from injecting code into other processes
Add-MpPreference -AttackSurfaceReductionRules_Ids "75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84" -AttackSurfaceReductionRules_Actions Enabled

# Block Win32 API calls from Office macro
Add-MpPreference -AttackSurfaceReductionRules_Ids "92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B" -AttackSurfaceReductionRules_Actions Enabled

# Block Office applications from creating executable content
Add-MpPreference -AttackSurfaceReductionRules_Ids "3B576869-A4EC-4529-8536-B80A7769E899" -AttackSurfaceReductionRules_Actions Enabled

# Block execution of potentially obfuscated scripts
Add-MpPreference -AttackSurfaceReductionRules_Ids "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC" -AttackSurfaceReductionRules_Actions Enabled

# Block executable content from email client and webmail
Add-MpPreference -AttackSurfaceReductionRules_Ids "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550" -AttackSurfaceReductionRules_Actions Enabled

# Block JavaScript or VBScript from launching downloaded executable content
Add-MpPreference -AttackSurfaceReductionRules_Ids "D3E037E1-3EB8-44C8-A917-57927947596D" -AttackSurfaceReductionRules_Actions Enabled

# Block executable files from running unless they meet a prevalence, age, or trusted list criteria
Add-MpPreference -AttackSurfaceReductionRules_Ids "01443614-cd74-433a-b99e-2ecdc07bfc25" -AttackSurfaceReductionRules_Actions Enabled

# Use advanced protection against ransomware
Add-MpPreference -AttackSurfaceReductionRules_Ids "C1DB55AB-C21A-4637-BB3F-A12568109D35" -AttackSurfaceReductionRules_Actions Enabled

# Block Win32 API calls from Office macro
Add-MpPreference -AttackSurfaceReductionRules_Ids "92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B" -AttackSurfaceReductionRules_Actions Enabled

# Block credential stealing from the Windows local security authority subsystem (lsass.exe)
Add-MpPreference -AttackSurfaceReductionRules_Ids "9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2" -AttackSurfaceReductionRules_Actions Enabled

# Block untrusted and unsigned processes that run from USB
Add-MpPreference -AttackSurfaceReductionRules_Ids "B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4" -AttackSurfaceReductionRules_Actions Enabled

# EDIT: Enable Controlled Folder Access - enable with caution
# Application installations may be blocked - admin elevation required to approve an app install through CFA
Set-MpPreference -EnableControlledFolderAccess Enabled
# To add exclusion folders or apps, use: Add-MpPreference -ExclusionPath 'C:\Program Files\App\app.exe'

# Enable Cloud functionality of Windows Defender
Set-MpPreference -MAPSReporting Advanced
Set-MpPreference -SubmitSamplesConsent SendAllSamples

# Enable Defender exploit system-wide protection
# The commented line includes CFG which can cause issues with apps like Discord & Mouse Without Borders
# Set-Processmitigation -System -Enable DEP,EmulateAtlThunks,BottomUp,HighEntropy,SEHOP,SEHOPTelemetry,TerminateOnError,CFG
Set-Processmitigation -System -Enable DEP,EmulateAtlThunks,BottomUp,HighEntropy,SEHOP,SEHOPTelemetry,TerminateOnError

# Enable Network protection
# Enabled - Users will not be able to access malicious IP addresses and domains
# Disable (Default) - The Network protection feature will not work. Users will not be blocked from accessing malicious domains
# AuditMode - If a user visits a malicious IP address or domain, an event will be recorded in the Windows event log but the user will not be blocked from visiting the address.
Set-MpPreference -EnableNetworkProtection Enabled

#######################################################################################################################
# Enable exploit protection (EMET on Windows 10)
# Download ProcessMitigation.xml and apply it

$policyUrl = "https://demo.wd.microsoft.com/Content/ProcessMitigation.xml"
$policyPath = "$env:TEMP\ProcessMitigation.xml"
Invoke-WebRequest -Uri $policyUrl -OutFile $policyPath
Set-ProcessMitigation -PolicyFilePath $policyPath
Remove-Item $policyPath

#######################################################################################################################
# Harden all version of MS Office against common malspam attacks
# Disables Macros, enables ProtectedView

$officePaths = @(
    "HKCU:\SOFTWARE\Microsoft\Office\12.0\Excel\Security",
    "HKCU:\SOFTWARE\Microsoft\Office\12.0\PowerPoint\Security",
    "HKCU:\SOFTWARE\Microsoft\Office\12.0\Word\Security",
    "HKCU:\SOFTWARE\Microsoft\Office\14.0\Excel\Security",
    "HKCU:\SOFTWARE\Microsoft\Office\14.0\PowerPoint\Security",
    "HKCU:\SOFTWARE\Microsoft\Office\14.0\Word\Security",
    "HKCU:\SOFTWARE\Microsoft\Office\15.0\Excel\Security",
    "HKCU:\SOFTWARE\Microsoft\Office\15.0\PowerPoint\Security",
    "HKCU:\SOFTWARE\Microsoft\Office\15.0\Word\Security",
    "HKCU:\SOFTWARE\Microsoft\Office\16.0\Excel\Security",
    "HKCU:\SOFTWARE\Microsoft\Office\16.0\PowerPoint\Security",
    "HKCU:\SOFTWARE\Microsoft\Office\16.0\Word\Security"
)

foreach ($path in $officePaths) {
    if (!(Test-Path $path)) {
        New-Item -Path $path -Force | Out-Null
    }
    
    # Set PackagerPrompt to 2 to disable
    Set-ItemProperty -Path $path -Name "PackagerPrompt" -Value 2 -Type DWord -ErrorAction SilentlyContinue
    
    # Set VBAWarnings to 4 to disable
    Set-ItemProperty -Path $path -Name "VBAWarnings" -Value 4 -Type DWord -ErrorAction SilentlyContinue
}

# Additional Excel specific settings
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\12.0\Excel\Security" -Name "WorkbookLinkWarnings" -Value 2 -Type DWord -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\14.0\Excel\Security" -Name "WorkbookLinkWarnings" -Value 2 -Type DWord -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\15.0\Excel\Security" -Name "WorkbookLinkWarnings" -Value 2 -Type DWord -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Excel\Security" -Name "WorkbookLinkWarnings" -Value 2 -Type DWord -ErrorAction SilentlyContinue

# Don't update links
if (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Office\14.0\Excel\Options")) {
    New-Item -Path "HKCU:\SOFTWARE\Microsoft\Office\14.0\Excel\Options" -Force | Out-Null
}
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\14.0\Excel\Options" -Name "DontUpdateLinks" -Value 1 -Type DWord -ErrorAction SilentlyContinue

if (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Office\15.0\Excel\Options")) {
    New-Item -Path "HKCU:\SOFTWARE\Microsoft\Office\15.0\Excel\Options" -Force | Out-Null
}
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\15.0\Excel\Options" -Name "DontUpdateLinks" -Value 1 -Type DWord -ErrorAction SilentlyContinue

if (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Excel\Options")) {
    New-Item -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Excel\Options" -Force | Out-Null
}
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Excel\Options" -Name "DontUpdateLinks" -Value 1 -Type DWord -ErrorAction SilentlyContinue

# Disable DDE
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\14.0\Word\Security" -Name "AllowDDE" -Value 0 -Type DWord -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\15.0\Word\Security" -Name "AllowDDE" -Value 0 -Type DWord -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Word\Security" -Name "AllowDDE" -Value 0 -Type DWord -ErrorAction SilentlyContinue

# Disable ActiveX
if (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Office\Common\Security")) {
    New-Item -Path "HKCU:\SOFTWARE\Microsoft\Office\Common\Security" -Force | Out-Null
}
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\Common\Security" -Name "DisableAllActiveX" -Value 1 -Type DWord -ErrorAction SilentlyContinue

# Disable open settings
if (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Office\12.0\Word\Options\vpref")) {
    New-Item -Path "HKCU:\SOFTWARE\Microsoft\Office\12.0\Word\Options\vpref" -Force | Out-Null
}
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\12.0\Word\Options\vpref" -Name "fNoCalclinksOnopen_90_1" -Value 1 -Type DWord -ErrorAction SilentlyContinue

#######################################################################################################################
# General OS hardening
# Disable DNS Multicast, NTLM, SMBv1, NetBIOS over TCP/IP, PowerShellV2, AutoRun, 8.3 names, Last Access timestamp and weak TLS/SSL ciphers and protocols
# Enables UAC, SMB/LDAP Signing, Show hidden files

# Enforce the Administrator role for adding printer drivers. This is a frequent exploit attack vector.
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers" -Name "AddPrinterDrivers" -Value 1 -Type DWord

# Forces Installer to NOT use elevated privileges during installs by default, which prevents escalation of privileges vulnerabilities and attacks
if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name "AlwaysInstallElevated" -Value 0 -Type DWord

# Disable storing password in memory in cleartext
if (!(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest")) {
    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential" -Value 0 -Type DWord

# Prevent Kerberos from using DES or RC4
if (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters")) {
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" -Name "SupportedEncryptionTypes" -Value 2147483640 -Type DWord

# DNS security settings
if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "DisableSmartNameResolution" -Value 1 -Type DWord

if (!(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters")) {
    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" -Name "DisableParallelAandAAAA" -Value 1 -Type DWord

# TCP/IP security settings
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "DisableIPSourceRouting" -Value 2 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "EnableICMPRedirect" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" -Name "DisableIPSourceRouting" -Value 2 -Type DWord

# Disable SMBv1
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "SMB1" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" -Name "RestrictNullSessAccess" -Value 1 -Type DWord

# Enable UAC
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableVirtualization" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 2 -Type DWord

# Security settings for attachments
if (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments")) {
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" -Name "SaveZoneInformation" -Value 2 -Type DWord

# Windows Explorer settings
if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoDataExecutionPrevention" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoHeapTerminationOnCorruption" -Value 0 -Type DWord

# WiFi settings
if (!(Test-Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config")) {
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Name "AutoConnectAllowedOEM" -Value 0 -Type DWord

if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" -Name "fMinimizeConnections" -Value 1 -Type DWord

# NetBT security
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netbt\Parameters" -Name "NoNameReleaseOnDemand" -Value 1 -Type DWord

# NTLM security
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -Name "NTLMMinServerSec" -Value 537395200 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -Name "NTLMMinClientSec" -Value 537395200 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\LSA\MSV1_0" -Name "allownullsessionfallback" -Value 0 -Type DWord

# LM compatibility
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LMCompatibilityLevel" -Value 5 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymousSAM" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymous" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "EveryoneIncludesAnonymous" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictRemoteSAM" -Value "O:BAG:BAD:(A;;RC;;;BA)" -Type String
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "UseMachineId" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LimitBlankPasswordUse" -Value 1 -Type DWord

# WPAD security
if (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad")) {
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad" -Name "WpadOverride" -Value 1 -Type DWord

# Force logoff if smart card removed - Set to "2" for logoff, set to "1" for lock
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "SCRemoveOption" -Value 2 -Type DWord

# Enable SMB/LDAP Signing
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanmanWorkStation\Parameters" -Name "RequireSecuritySignature" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanmanWorkStation\Parameters" -Name "EnableSecuritySignature" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters" -Name "RequireSecuritySignature" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters" -Name "EnableSecuritySignature" -Value 1 -Type DWord

# 1- Negotiated; 2-Required
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\NTDS\Parameters" -Name "LDAPServerIntegrity" -Value 2 -Type DWord
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\ldap" -Name "LDAPClientIntegrity" -Value 1 -Type DWord

# Domain member settings
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters" -Name "RequireSignOrSeal" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters" -Name "SealSecureChannel" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters" -Name "SignSecureChannel" -Value 1 -Type DWord

# Enable SmartScreen
if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableSmartScreen" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "ShellSmartScreenLevel" -Value "Block" -Type String

# Prevent (remote) DLL Hijacking
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name "CWDIllegalInDllSearch" -Value 2 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name "SafeDLLSearchMode" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name "ProtectionMode" -Value 1 -Type DWord

# Disable (c|w)script.exe to prevent the system from running VBS scripts
if (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows Script Host\Settings")) {
    New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows Script Host\Settings" -Force | Out-Null
}
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows Script Host\Settings" -Name "Enabled" -Value 0 -Type DWord
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows Script Host\Settings" -Name "ActiveDebugging" -Value 1 -Type String
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows Script Host\Settings" -Name "DisplayLogo" -Value 1 -Type String
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows Script Host\Settings" -Name "SilentTerminate" -Value 0 -Type String
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows Script Host\Settings" -Name "UseWINSAFER" -Value 1 -Type String

# Disable IPv6
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\tcpip6\parameters" -Name "DisabledComponents" -Value 0xFF -Type DWord

# Windows Remote Access Settings
# Disable solicited remote assistance
if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fAllowToGetHelp" -Value 0 -Type DWord
# Require encrypted RPC connections to Remote Desktop
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fEncryptRPCTraffic" -Value 1 -Type DWord

# Removal Media Settings
# Disable autorun/autoplay on all drives
if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoAutoplayfornonVolume" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer" -Name "NoDriveTypeAutoRun" -Value 255 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoAutorun" -Value 1 -Type DWord

# Stop WinRM Service
Stop-Service -Name "WinRM" -Force -ErrorAction SilentlyContinue
if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" -Name "AllowUnencryptedTraffic" -Value 0 -Type DWord

# Disable WinRM Client Digest authentication
if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" -Name "AllowDigest" -Value 0 -Type DWord
Start-Service -Name "WinRM" -ErrorAction SilentlyContinue

# Disabling RPC usage from a remote asset interacting with scheduled tasks
if (!(Test-Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Schedule")) {
    New-Item -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Schedule" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Schedule" -Name "DisableRpcOverTcp" -Value 1 -Type DWord

# Disabling RPC usage from a remote asset interacting with services
Set-ItemProperty -Path "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control" -Name "DisableRemoteScmEndpoints" -Value 1 -Type DWord

# Stop NetBIOS over TCP/IP
Get-WmiObject -Class Win32_NetworkAdapterConfiguration | Where-Object { $_.TcpipNetbiosOptions -eq 0 } | ForEach-Object { $_.SetTcpipNetbios(2) }
Get-WmiObject -Class Win32_NetworkAdapterConfiguration | Where-Object { $_.TcpipNetbiosOptions -eq 1 } | ForEach-Object { $_.SetTcpipNetbios(2) }

# Disable NTLMv1
Disable-WindowsOptionalFeature -Online -FeatureName smb1protocol -NoRestart
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10" -Name "Start" -Value 4 -Type DWord

# Disable Powershellv2
Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2 -NoRestart
Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -NoRestart

#######################################################################
# Harden lsass to help protect against credential dumping (Mimikatz)
# Configures lsass.exe as a protected process and disables wdigest
# Enables delegation of non-exported credentials which enables support for Restricted Admin Mode or Remote Credential Guard

if (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe")) {
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe" -Name "AuditLevel" -Value 8 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "DisableRestrictedAdmin" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "DisableRestrictedAdminOutboundCreds" -Value 1 -Type DWord

if (!(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest")) {
    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "Negotiate" -Value 0 -Type DWord

if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation" -Name "AllowProtectedCreds" -Value 1 -Type DWord

#######################################################################
# Disable the ClickOnce trust prompt
# This only partially mitigates the risk of malicious ClickOnce Apps - the ability to run the manifest is disabled, but hash retrieval is still possible

$netFrameworkPaths = @(
    "HKLM:\SOFTWARE\MICROSOFT\.NETFramework\Security\TrustManager\PromptingLevel"
)

foreach ($path in $netFrameworkPaths) {
    if (!(Test-Path $path)) {
        New-Item -Path $path -Force | Out-Null
    }
    
    Set-ItemProperty -Path $path -Name "MyComputer" -Value "Disabled" -Type String
    Set-ItemProperty -Path $path -Name "LocalIntranet" -Value "Disabled" -Type String
    Set-ItemProperty -Path $path -Name "Internet" -Value "Disabled" -Type String
    Set-ItemProperty -Path $path -Name "TrustedSites" -Value "Disabled" -Type String
    Set-ItemProperty -Path $path -Name "UntrustedSites" -Value "Disabled" -Type String
}

#######################################################################
# Enable Windows Firewall and configure some advanced options
# Block Win32/64 binaries (LOLBins) from making net connections when they shouldn't

# Enable firewall on all profiles
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True

# Define an array of paths to block network connections from
$blockNetworkPaths = @(
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
    "$env:SystemRoot\SysWOW64\wscript.exe",
    "$env:ProgramFiles\Microsoft Office\root\client\AppVLP.exe",
    "${env:ProgramFiles(x86)}\Microsoft Office\root\client\AppVLP.exe"
)

# Create firewall rules for each path
foreach ($path in $blockNetworkPaths) {
    if (Test-Path $path) {
        $ruleName = "Block $(Split-Path $path -Leaf) netconns"
        New-NetFirewallRule -DisplayName $ruleName -Direction Outbound -Program $path -Protocol TCP -Action Block -Profile Any -ErrorAction SilentlyContinue
    }
}

# Disable TCP timestamps
netsh int tcp set global timestamps=disabled

# Enable Firewall Logging
netsh advfirewall set currentprofile logging filename "%systemroot%\system32\LogFiles\Firewall\pfirewall.log"
netsh advfirewall set currentprofile logging maxfilesize 4096
netsh advfirewall set currentprofile logging droppedconnections enable

# Disable AutoRun
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Value 0xFF -Type DWord
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Value 0xFF -Type DWord

# Show known file extensions and hidden files
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Value 0 -Type DWord
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -Value 1 -Type DWord
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowSuperHidden" -Value 1 -Type DWord
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowSuperHidden" -Value 1 -Type DWord

# Disable 8.3 names (Mitigate Microsoft IIS tilde directory enumeration) and Last Access timestamp for files and folder
fsutil behavior set disable8dot3 1
fsutil behavior set disablelastaccess 0

# Biometrics
# Enable anti-spoofing for facial recognition
if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures" -Name "EnhancedAntiSpoofing" -Value 1 -Type DWord

# Disable other camera use while screen is locked
if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" -Name "NoLockScreenCamera" -Value 1 -Type DWord

# Prevent Windows app voice activation while locked
if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsActivateWithVoiceAboveLock" -Value 2 -Type DWord
# Prevent Windows app voice activation entirely (be mindful of those with accessibility needs)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsActivateWithVoice" -Value 2 -Type DWord

#######################################################################
# Disable weak TLS/SSL ciphers and protocols
#######################################################################

# Create required registry paths if they don't exist
$tlsPaths = @(
    "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\AES 128/128",
    "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\AES 256/256",
    "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\DES 56/56",
    "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\NULL",
    "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 128/128",
    "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 40/128",
    "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 56/128",
    "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 128/128",
    "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 40/128",
    "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 56/128",
    "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 64/128",
    "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 168",
    "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\MD5",
    "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA",
    "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA256",
    "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA384",
    "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA512",
    "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman",
    "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\ECDH",
    "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\PKCS",
    "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Client",
    "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Server",
    "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Client",
    "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Server",
    "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client",
    "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server",
    "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client",
    "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server",
    "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client",
    "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server",
    "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client",
    "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server",
    "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client",
    "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server"
)

foreach ($path in $tlsPaths) {
    if (!(Test-Path $path)) {
        New-Item -Path $path -Force | Out-Null
    }
}

# Encryption - Ciphers: AES only
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\AES 128/128" -Name "Enabled" -Value 0xffffffff -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\AES 256/256" -Name "Enabled" -Value 0xffffffff -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\DES 56/56" -Name "Enabled" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\NULL" -Name "Enabled" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 128/128" -Name "Enabled" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 40/128" -Name "Enabled" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 56/128" -Name "Enabled" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 128/128" -Name "Enabled" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 40/128" -Name "Enabled" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 56/128" -Name "Enabled" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 64/128" -Name "Enabled" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 168" -Name "Enabled" -Value 0 -Type DWord

# Encryption - Hashes: All allowed
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\MD5" -Name "Enabled" -Value 0xffffffff -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA" -Name "Enabled" -Value 0xffffffff -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA256" -Name "Enabled" -Value 0xffffffff -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA384" -Name "Enabled" -Value 0xffffffff -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA512" -Name "Enabled" -Value 0xffffffff -Type DWord

# Encryption - Key Exchanges: All allowed
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman" -Name "Enabled" -Value 0xffffffff -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman" -Name "ServerMinKeyBitLength" -Value 0x00001000 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\ECDH" -Name "Enabled" -Value 0xffffffff -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\PKCS" -Name "Enabled" -Value 0xffffffff -Type DWord

# Encryption - Protocols: TLS 1.0 and higher
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Client" -Name "Enabled" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Client" -Name "DisabledByDefault" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Server" -Name "Enabled" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Server" -Name "DisabledByDefault" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Client" -Name "Enabled" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Client" -Name "DisabledByDefault" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Server" -Name "Enabled" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Server" -Name "DisabledByDefault" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client" -Name "Enabled" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client" -Name "DisabledByDefault" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server" -Name "Enabled" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server" -Name "DisabledByDefault" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client" -Name "Enabled" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client" -Name "DisabledByDefault" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server" -Name "Enabled" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server" -Name "DisabledByDefault" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client" -Name "Enabled" -Value 0xffffffff -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client" -Name "DisabledByDefault" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" -Name "Enabled" -Value 0xffffffff -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" -Name "DisabledByDefault" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client" -Name "Enabled" -Value 0xffffffff -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client" -Name "DisabledByDefault" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" -Name "Enabled" -Value 0xffffffff -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" -Name "DisabledByDefault" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client" -Name "Enabled" -Value 0xffffffff -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client" -Name "DisabledByDefault" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" -Name "Enabled" -Value 0xffffffff -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" -Name "DisabledByDefault" -Value 0 -Type DWord

# Encryption - Cipher Suites (order) - All cipher included to avoid application problems
if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002" -Name "Functions" -Value "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,TLS_RSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_128_GCM_SHA256,TLS_RSA_WITH_AES_256_CBC_SHA256,TLS_RSA_WITH_AES_128_CBC_SHA256,TLS_RSA_WITH_AES_256_CBC_SHA,TLS_RSA_WITH_AES_128_CBC_SHA,TLS_AES_256_GCM_SHA384,TLS_AES_128_GCM_SHA256,TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,TLS_RSA_WITH_3DES_EDE_CBC_SHA,TLS_RSA_WITH_NULL_SHA256,TLS_RSA_WITH_NULL_SHA,TLS_PSK_WITH_AES_256_GCM_SHA384,TLS_PSK_WITH_AES_128_GCM_SHA256,TLS_PSK_WITH_AES_256_CBC_SHA384,TLS_PSK_WITH_AES_128_CBC_SHA256,TLS_PSK_WITH_NULL_SHA384,TLS_PSK_WITH_NULL_SHA256" -Type String

# Enabling Strong Authentication for .NET Framework 3.5
if (!(Test-Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727")) {
    New-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727" -Name "SchUseStrongCrypto" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727" -Name "SystemDefaultTlsVersions" -Value 1 -Type DWord

if (!(Test-Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727")) {
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727" -Name "SchUseStrongCrypto" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727" -Name "SystemDefaultTlsVersions" -Value 1 -Type DWord

# Enabling Strong Authentication for .NET Framework 4.0/4.5.x
if (!(Test-Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319")) {
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319" -Name "SchUseStrongCrypto" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319" -Name "SystemDefaultTlsVersions" -Value 1 -Type DWord

#######################################################################
# Enable and Configure Internet Browser Settings
#######################################################################

# Enable SmartScreen for Edge
if (!(Test-Path "HKCU:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter")) {
    New-Item -Path "HKCU:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" -Force | Out-Null
}
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" -Name "EnabledV9" -Value 1 -Type DWord

# Enable Notifications in IE when a site attempts to install software
if (!(Test-Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer")) {
    New-Item -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Force | Out-Null
}
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name "SafeForScripting" -Value 0 -Type DWord

# Disable Edge password manager to encourage use of proper password manager
if (!(Test-Path "HKCU:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main")) {
    New-Item -Path "HKCU:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" -Force | Out-Null
}
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" -Name "FormSuggest Passwords" -Value "no" -Type String

#######################################################################
# Windows 10 Privacy Settings
#######################################################################

# Set Windows Analytics to limited enhanced if enhanced is enabled
if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "LimitEnhancedDiagnosticDataWindowsAnalytics" -Value 1 -Type DWord

# Set Windows Telemetry to security only
# If you intend to use Enhanced for Windows Analytics then set this to "2" instead
# Note that W10 Home edition will do a minimum of "Basic"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "MaxTelemetryAllowed" -Value 1 -Type DWord

if (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack")) {
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" -Name "ShowedToastAtLevel" -Value 1 -Type DWord

# Disable location data
if (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore")) {
    New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore" -Force | Out-Null
}
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore" -Name "Location" -Value "Deny" -Type String

# Prevent the Start Menu Search from providing internet results and using your location
if (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search")) {
    New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Force | Out-Null
}
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -Value 0 -Type DWord
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "AllowSearchToUseLocation" -Value 0 -Type DWord
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "CortanaConsent" -Value 0 -Type DWord

# Disable publishing of Win10 user activity
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "PublishUserActivities" -Value 1 -Type DWord

# Disable Win10 settings sync to cloud
if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableSettingSync" -Value 2 -Type DWord

# Disable the advertising ID
if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Name "DisabledByGroupPolicy" -Value 1 -Type DWord

# Disable Windows GameDVR (Broadcasting and Recording)
if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Name "AllowGameDVR" -Value 0 -Type DWord

# Disable Microsoft consumer experience which prevent notifications of suggested applications to install
if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Value 1 -Type DWord

if (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager")) {
    New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Force | Out-Null
}
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SystemPaneSuggestionsEnabled" -Value 0 -Type DWord
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SilentInstalledAppsEnabled" -Value 0 -Type DWord
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEnabled" -Value 0 -Type DWord
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "OemPreInstalledAppsEnabled" -Value 0 -Type DWord

# Disable websites accessing local language list
if (!(Test-Path "HKCU:\Control Panel\International\User Profile")) {
    New-Item -Path "HKCU:\Control Panel\International\User Profile" -Force | Out-Null
}
Set-ItemProperty -Path "HKCU:\Control Panel\International\User Profile" -Name "HttpAcceptLanguageOptOut" -Value 1 -Type DWord

# Prevent toast notifications from appearing on lock screen
if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "NoToastApplicationNotificationOnLockScreen" -Value 1 -Type DWord

#######################################################################
# Enable Advanced Windows Logging
#######################################################################

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
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -Type DWord

# Enabled Advanced Settings
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "SCENoApplyLegacyAuditPolicy" -Value 1 -Type DWord

# Enable PowerShell Logging
if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Name "EnableModuleLogging" -Value 1 -Type DWord

if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1 -Type DWord

# Enable Windows Event Detailed Logging
# This is intentionally meant to be a subset of expected enterprise logging as this script may be used on consumer devices.
# For more extensive Windows logging, see: https://www.malwarearchaeology.com/cheat-sheets
auditpol /set /subcategory:"Security Group Management" /success:enable /failure:enable
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
auditpol /set /subcategory:"Logoff" /success:enable /failure:disable
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Removable Storage" /success:enable /failure:enable
auditpol /set /subcategory:"SAM" /success:disable /failure:disable
auditpol /set /subcategory:"Filtering Platform Policy Change" /success:disable /failure:disable
auditpol /set /subcategory:"Security State Change" /success:enable /failure:enable
auditpol /set /subcategory:"Security System Extension" /success:enable /failure:enable
auditpol /set /subcategory:"System Integrity" /success:enable /failure:enable

#######################################################################
# Uninstall built-in Windows 10 apps
#######################################################################

# Uninstall common extra apps found on a lot of Win10 installs
# Review to ensure it isn't removing any apps you or your user need to use.

$appsToRemove = @(
    "Microsoft.BingWeather",
    "Microsoft.GetHelp",
    "Microsoft.Getstarted",
    "Microsoft.Messaging",
    "Microsoft.Microsoft3DViewer",
    "Microsoft.MicrosoftOfficeHub",
    "Microsoft.MicrosoftSolitaireCollection",
    "Microsoft.MixedReality.Portal",
    "Microsoft.OneConnect",
    "Microsoft.Print3D",
    "Microsoft.Wallet",
    "Microsoft.WebMediaExtensions",
    "Microsoft.WebpImageExtension",
    "microsoft.windowscommunicationsapps",
    "Microsoft.WindowsFeedbackHub",
    "Microsoft.WindowsMaps",
    "Microsoft.WindowsSoundRecorder",
    "Microsoft.Xbox.TCUI",
    "Microsoft.XboxApp",
    "Microsoft.XboxGameOverlay",
    "Microsoft.XboxGamingOverlay",
    "Microsoft.XboxIdentityProvider",
    "Microsoft.XboxSpeechToTextOverlay",
    "Microsoft.YourPhone",
    "Microsoft.ZuneMusic",
    "Microsoft.ZuneVideo",
    "Microsoft.WindowsFeedback",
    "Windows.ContactSupport",
    "PandoraMedia",
    "AdobeSystemIncorporated.AdobePhotoshop",
    "Duolingo",
    "Microsoft.BingNews",
    "Microsoft.Office.Sway",
    "Microsoft.Advertising.Xaml",
    "Microsoft.Services.Store.Engagement",
    "ActiproSoftware",
    "EclipseManager",
    "SpotifyAB.SpotifyMusic",
    "king.com.",
    "Microsoft.NET.Native.Framework.1."
)

foreach ($app in $appsToRemove) {
    Get-AppxPackage -Name $app -AllUsers | Remove-AppxPackage -ErrorAction SilentlyContinue
    Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -eq $app } | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue
}

#######################################################################
# Adobe Reader DC STIG
#######################################################################

# Create required registry keys if they don't exist
$adobePaths = @(
    "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cCloud",
    "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cDefaultLaunchURLPerms",
    "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cServices",
    "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cSharePoint",
    "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cWebmailProfiles",
    "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cWelcomeScreen",
    "HKLM:\Software\Adobe\Acrobat Reader\DC\Installer",
    "HKLM:\Software\Wow6432Node\Adobe\Acrobat Reader\DC\Installer"
)

foreach ($path in $adobePaths) {
    if (!(Test-Path $path)) {
        New-Item -Path $path -Force | Out-Null
    }
}

# Set Adobe Reader DC security settings
Set-ItemProperty -Path "HKLM:\Software\Adobe\Acrobat Reader\DC\Installer" -Name "DisableMaintenance" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" -Name "bAcroSuppressUpsell" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" -Name "bDisablePDFHandlerSwitching" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" -Name "bDisableTrustedFolders" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" -Name "bDisableTrustedSites" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" -Name "bEnableFlash" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" -Name "bEnhancedSecurityInBrowser" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" -Name "bEnhancedSecurityStandalone" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" -Name "bProtectedMode" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" -Name "iFileAttachmentPerms" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" -Name "iProtectedView" -Value 2 -Type DWord
Set-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cCloud" -Name "bAdobeSendPluginToggle" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cDefaultLaunchURLPerms" -Name "iURLPerms" -Value 3 -Type DWord
Set-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cDefaultLaunchURLPerms" -Name "iUnknownURLPerms" -Value 2 -Type DWord
Set-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cServices" -Name "bToggleAdobeDocumentServices" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cServices" -Name "bToggleAdobeSign" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cServices" -Name "bTogglePrefsSync" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cServices" -Name "bToggleWebConnectors" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cServices" -Name "bUpdater" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cSharePoint" -Name "bDisableSharePointFeatures" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cWebmailProfiles" -Name "bDisableWebmail" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cWelcomeScreen" -Name "bShowWelcomeScreen" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\Software\Wow6432Node\Adobe\Acrobat Reader\DC\Installer" -Name "DisableMaintenance" -Value 1 -Type DWord

#######################################################################
# Browser hardening - Edge and Chrome
#######################################################################

# Prevent Edge from running in background
if (!(Test-Path "HKLM:\Software\Policies\Microsoft\Edge")) {
    New-Item -Path "HKLM:\Software\Policies\Microsoft\Edge" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Edge" -Name "BackgroundModeEnabled" -Value 0 -Type DWord

# Edge hardening
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Edge" -Name "SitePerProcess" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Edge" -Name "SSLVersionMin" -Value "tls1.2^@" -Type String
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Edge" -Name "NativeMessagingUserLevelHosts" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Edge" -Name "SmartScreenEnabled" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Edge" -Name "PreventSmartScreenPromptOverride" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Edge" -Name "PreventSmartScreenPromptOverrideForFiles" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Edge" -Name "SSLErrorOverrideAllowed" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Edge" -Name "SmartScreenPuaEnabled" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Edge" -Name "AllowDeletingBrowserHistory" -Value 0 -Type DWord

# Edge extension settings
if (!(Test-Path "HKLM:\Software\Policies\Microsoft\Edge\ExtensionInstallAllowlist")) {
    New-Item -Path "HKLM:\Software\Policies\Microsoft\Edge\ExtensionInstallAllowlist" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Edge\ExtensionInstallAllowlist\1" -Value "odfafepnkmbhccpbejgmiehpchacaeak" -Type String

if (!(Test-Path "HKLM:\Software\Policies\Microsoft\Edge\ExtensionInstallForcelist")) {
    New-Item -Path "HKLM:\Software\Policies\Microsoft\Edge\ExtensionInstallForcelist" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Edge\ExtensionInstallForcelist\1" -Value "odfafepnkmbhccpbejgmiehpchacaeak" -Type String

if (!(Test-Path "HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Edge\Extensions\odfafepnkmbhccpbejgmiehpchacaeak")) {
    New-Item -Path "HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Edge\Extensions\odfafepnkmbhccpbejgmiehpchacaeak" -Force | Out-Null
}
Set-ItemProperty -Path "HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Edge\Extensions\odfafepnkmbhccpbejgmiehpchacaeak" -Name "update_url" -Value "https://edge.microsoft.com/extensionwebstorebase/v1/crx" -Type String

#######################################################################
# Enable and Configure Google Chrome Internet Browser Settings
#######################################################################

if (!(Test-Path "HKLM:\SOFTWARE\Policies\Google\Chrome")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Force | Out-Null
}

# Basic Chrome security settings
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name "AllowCrossOriginAuthPrompt" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name "AlwaysOpenPdfExternally" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name "AmbientAuthenticationInPrivateModesEnabled" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name "AudioCaptureAllowed" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name "AudioSandboxEnabled" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name "DnsOverHttpsMode" -Value "on" -Type String
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name "ScreenCaptureAllowed" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name "SitePerProcess" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name "TLS13HardeningForLocalAnchorsEnabled" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name "VideoCaptureAllowed" -Value 1 -Type DWord

# More Chrome hardening settings
Set-ItemProperty -Path "HKLM:\Software\Policies\Google\Chrome" -Name "AdvancedProtectionAllowed" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\Software\Policies\Google\Chrome" -Name "RemoteAccessHostFirewallTraversal" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\Software\Policies\Google\Chrome" -Name "DefaultPopupsSetting" -Value 33554432 -Type DWord
Set-ItemProperty -Path "HKLM:\Software\Policies\Google\Chrome" -Name "DefaultGeolocationSetting" -Value 33554432 -Type DWord
Set-ItemProperty -Path "HKLM:\Software\Policies\Google\Chrome" -Name "AllowOutdatedPlugins" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\Software\Policies\Google\Chrome" -Name "BackgroundModeEnabled" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\Software\Policies\Google\Chrome" -Name "CloudPrintProxyEnabled" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\Software\Policies\Google\Chrome" -Name "MetricsReportingEnabled" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\Software\Policies\Google\Chrome" -Name "SearchSuggestEnabled" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\Software\Policies\Google\Chrome" -Name "ImportSavedPasswords" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\Software\Policies\Google\Chrome" -Name "IncognitoModeAvailability" -Value 16777216 -Type DWord
Set-ItemProperty -Path "HKLM:\Software\Policies\Google\Chrome" -Name "EnableOnlineRevocationChecks" -Value 16777216 -Type DWord
Set-ItemProperty -Path "HKLM:\Software\Policies\Google\Chrome" -Name "SavingBrowserHistoryDisabled" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\Software\Policies\Google\Chrome" -Name "DefaultPluginsSetting" -Value 50331648 -Type DWord
Set-ItemProperty -Path "HKLM:\Software\Policies\Google\Chrome" -Name "AllowDeletingBrowserHistory" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\Software\Policies\Google\Chrome" -Name "PromptForDownloadLocation" -Value 16777216 -Type DWord
Set-ItemProperty -Path "HKLM:\Software\Policies\Google\Chrome" -Name "DownloadRestrictions" -Value 33554432 -Type DWord
Set-ItemProperty -Path "HKLM:\Software\Policies\Google\Chrome" -Name "AutoplayAllowed" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\Software\Policies\Google\Chrome" -Name "SafeBrowsingExtendedReportingEnabled" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\Software\Policies\Google\Chrome" -Name "DefaultWebUsbGuardSetting" -Value 33554432 -Type DWord
Set-ItemProperty -Path "HKLM:\Software\Policies\Google\Chrome" -Name "ChromeCleanupEnabled" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\Software\Policies\Google\Chrome" -Name "ChromeCleanupReportingEnabled" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\Software\Policies\Google\Chrome" -Name "EnableMediaRouter" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\Software\Policies\Google\Chrome" -Name "SSLVersionMin" -Value "tls1.1" -Type String
Set-ItemProperty -Path "HKLM:\Software\Policies\Google\Chrome" -Name "UrlKeyedAnonymizedDataCollectionEnabled" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\Software\Policies\Google\Chrome" -Name "WebRtcEventLogCollectionAllowed" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\Software\Policies\Google\Chrome" -Name "NetworkPredictionOptions" -Value 33554432 -Type DWord
Set-ItemProperty -Path "HKLM:\Software\Policies\Google\Chrome" -Name "BrowserGuestModeEnabled" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\Software\Policies\Google\Chrome" -Name "ImportAutofillFormData" -Value 0 -Type DWord

# Chrome extension settings
if (!(Test-Path "HKLM:\Software\Policies\Google\Chrome\ExtensionInstallWhitelist")) {
    New-Item -Path "HKLM:\Software\Policies\Google\Chrome\ExtensionInstallWhitelist" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\Software\Policies\Google\Chrome\ExtensionInstallWhitelist\1" -Value "cjpalhdlnbpafiamejdnhcphjbkeiagm" -Type String

if (!(Test-Path "HKLM:\Software\Policies\Google\Chrome\ExtensionInstallForcelist")) {
    New-Item -Path "HKLM:\Software\Policies\Google\Chrome\ExtensionInstallForcelist" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\Software\Policies\Google\Chrome\ExtensionInstallForcelist\1" -Value "cjpalhdlnbpafiamejdnhcphjbkeiagm" -Type String

if (!(Test-Path "HKLM:\Software\Policies\Google\Chrome\URLBlacklist")) {
    New-Item -Path "HKLM:\Software\Policies\Google\Chrome\URLBlacklist" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\Software\Policies\Google\Chrome\URLBlacklist\1" -Value "javascript://*" -Type String

if (!(Test-Path "HKLM:\Software\Policies\Google\Update")) {
    New-Item -Path "HKLM:\Software\Policies\Google\Update" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\Software\Policies\Google\Update" -Name "AutoUpdateCheckPeriodMinutes" -Value 1613168640 -Type DWord

if (!(Test-Path "HKLM:\Software\Policies\Google\Chrome\Recommended")) {
    New-Item -Path "HKLM:\Software\Policies\Google\Chrome\Recommended" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\Software\Policies\Google\Chrome\Recommended" -Name "SafeBrowsingProtectionLevel" -Value 2 -Type DWord

# Enforce device driver signing
BCDEDIT /set nointegritychecks OFF

Write-Host "Windows 10 hardening completed. It is recommended to restart your computer for all changes to take effect." -ForegroundColor Green