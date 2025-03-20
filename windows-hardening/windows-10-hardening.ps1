###############################################################################################################
#
#    Atlant Security (https://atlantsecurity.com)'s Windows 10 Security Hardening Script - 
#    includes Microsoft 365, Office, Chrome, Adobe Reader, Edge security settings.
#    PowerShell version of the original batch script.
#    License: Free to use for personal use. For commercial use, contact Atlant security at https://atlantsecurity.com/
#
###############################################################################################################
# INSTRUCTIONS
# It is a good idea to create a System Restore point before you run the script - as there are more than 920 lines in it,
# finding out which line broke your machine is going to be tricky. The script will create a restore point for you,
# but you can also create one manually.

# HOW TO RUN THE SCRIPT
# 1. In Settings, search for Restore, then choose Create a restore point, then in System Protection, make sure it is On and has at least 6% of the drive.
# 2. Run PowerShell as Administrator
# 3. Run this script
# 4. If you experience problems and need to roll back, roll back using the system restore point you created.

# Enable TLS 1.2 for PowerShell downloads
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

###############################################################################################################
# Create System Restore Point
###############################################################################################################

Write-Output "Creating system restore point..."
Enable-ComputerRestore -Drive "C:\"
vssadmin resize shadowstorage /on=c: /for=c: /maxsize=5000MB
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\PKCS" -Name "Enabled" -Value 0xffffffff -Type DWord

# Encryption - Protocols: TLS 1.0 and higher
New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Client" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Client" -Name "Enabled" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Client" -Name "DisabledByDefault" -Value 1 -Type DWord
New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Server" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Server" -Name "Enabled" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Server" -Name "DisabledByDefault" -Value 1 -Type DWord

New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Client" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Client" -Name "Enabled" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Client" -Name "DisabledByDefault" -Value 1 -Type DWord
New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Server" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Server" -Name "Enabled" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Server" -Name "DisabledByDefault" -Value 1 -Type DWord

New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client" -Name "Enabled" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client" -Name "DisabledByDefault" -Value 1 -Type DWord
New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server" -Name "Enabled" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server" -Name "DisabledByDefault" -Value 1 -Type DWord

New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client" -Name "Enabled" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client" -Name "DisabledByDefault" -Value 1 -Type DWord
New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server" -Name "Enabled" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server" -Name "DisabledByDefault" -Value 1 -Type DWord

New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client" -Name "Enabled" -Value 0xffffffff -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client" -Name "DisabledByDefault" -Value 0 -Type DWord
New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" -Name "Enabled" -Value 0xffffffff -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" -Name "DisabledByDefault" -Value 0 -Type DWord

New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client" -Name "Enabled" -Value 0xffffffff -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client" -Name "DisabledByDefault" -Value 0 -Type DWord
New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" -Name "Enabled" -Value 0xffffffff -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" -Name "DisabledByDefault" -Value 0 -Type DWord

New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client" -Name "Enabled" -Value 0xffffffff -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client" -Name "DisabledByDefault" -Value 0 -Type DWord
New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" -Name "Enabled" -Value 0xffffffff -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" -Name "DisabledByDefault" -Value 0 -Type DWord

# Enabling Strong Authentication for .NET Framework 3.5
New-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727" -Name "SchUseStrongCrypto" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727" -Name "SystemDefaultTlsVersions" -Value 1 -Type DWord
New-Item -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727" -Name "SchUseStrongCrypto" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727" -Name "SystemDefaultTlsVersions" -Value 1 -Type DWord

# Enabling Strong Authentication for .NET Framework 4.0/4.5.x
New-Item -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319" -Name "SchUseStrongCrypto" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319" -Name "SystemDefaultTlsVersions" -Value 1 -Type DWord

###############################################################################################################
# Enable and Configure Internet Browser Settings - Edge
###############################################################################################################

Write-Output "Configuring Edge browser security settings..."

# Enable SmartScreen for Edge
New-Item -Path "HKCU:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" -Name "EnabledV9" -Value 1 -Type DWord

# Enable Notifications in IE when a site attempts to install software
New-Item -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name "SafeForScripting" -Value 0 -Type DWord

# Disable Edge password manager to encourage use of proper password manager
New-Item -Path "HKCU:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" -Name "FormSuggest Passwords" -Value "no" -Type String

# Prevent Edge from running in background
New-Item -Path "HKLM:\Software\Policies\Microsoft\Edge" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Edge" -Name "BackgroundModeEnabled" -Value 0 -Type DWord

# EDGE HARDENING
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Edge" -Name "SitePerProcess" -Value 0x00000001 -Type DWord
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Edge" -Name "SSLVersionMin" -Value "tls1.2^@" -Type String
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Edge" -Name "NativeMessagingUserLevelHosts" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Edge" -Name "SmartScreenEnabled" -Value 0x00000001 -Type DWord
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Edge" -Name "PreventSmartScreenPromptOverride" -Value 0x00000001 -Type DWord
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Edge" -Name "PreventSmartScreenPromptOverrideForFiles" -Value 0x00000001 -Type DWord
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Edge" -Name "SSLErrorOverrideAllowed" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Edge" -Name "SmartScreenPuaEnabled" -Value 0x00000001 -Type DWord
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Edge" -Name "AllowDeletingBrowserHistory" -Value 0x00000000 -Type DWord

New-Item -Path "HKLM:\Software\Policies\Microsoft\Edge\ExtensionInstallAllowlist" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Edge\ExtensionInstallAllowlist" -Name "1" -Value "odfafepnkmbhccpbejgmiehpchacaeak" -Type String

New-Item -Path "HKLM:\Software\Policies\Microsoft\Edge\ExtensionInstallForcelist" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Edge\ExtensionInstallForcelist" -Name "1" -Value "odfafepnkmbhccpbejgmiehpchacaeak" -Type String

New-Item -Path "HKLM:\Software\Wow6432Node\Microsoft\Edge\Extensions\odfafepnkmbhccpbejgmiehpchacaeak" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\Software\Wow6432Node\Microsoft\Edge\Extensions\odfafepnkmbhccpbejgmiehpchacaeak" -Name "update_url" -Value "https://edge.microsoft.com/extensionwebstorebase/v1/crx" -Type String

###############################################################################################################
# Enable and Configure Google Chrome Internet Browser Settings
###############################################################################################################

Write-Output "Configuring Chrome browser security settings..."

New-Item -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Force | Out-Null
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

# Chrome hardening settings
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

New-Item -Path "HKLM:\Software\Policies\Google\Chrome\ExtensionInstallWhitelist" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\Software\Policies\Google\Chrome\ExtensionInstallWhitelist" -Name "1" -Value "cjpalhdlnbpafiamejdnhcphjbkeiagm" -Type String

New-Item -Path "HKLM:\Software\Policies\Google\Chrome\ExtensionInstallForcelist" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\Software\Policies\Google\Chrome\ExtensionInstallForcelist" -Name "1" -Value "cjpalhdlnbpafiamejdnhcphjbkeiagm" -Type String

New-Item -Path "HKLM:\Software\Policies\Google\Chrome\URLBlacklist" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\Software\Policies\Google\Chrome\URLBlacklist" -Name "1" -Value "javascript://*" -Type String

New-Item -Path "HKLM:\Software\Policies\Google\Update" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\Software\Policies\Google\Update" -Name "AutoUpdateCheckPeriodMinutes" -Value 1613168640 -Type DWord

New-Item -Path "HKLM:\Software\Policies\Google\Chrome\Recommended" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\Software\Policies\Google\Chrome\Recommended" -Name "SafeBrowsingProtectionLevel" -Value 2 -Type DWord

###############################################################################################################
# Windows 10 Privacy Settings
###############################################################################################################

Write-Output "Configuring Windows 10 privacy settings..."

# Set Windows Analytics to limited enhanced if enhanced is enabled
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "LimitEnhancedDiagnosticDataWindowsAnalytics" -Value 1 -Type DWord

# Set Windows Telemetry to security only
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "MaxTelemetryAllowed" -Value 1 -Type DWord
New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" -Name "ShowedToastAtLevel" -Value 1 -Type DWord

# Disable location data
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore" -Name "Location" -Value "Deny" -Type String

# Prevent the Start Menu Search from providing internet results and using your location
New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -Value 0 -Type DWord
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "AllowSearchToUseLocation" -Value 0 -Type DWord
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "CortanaConsent" -Value 0 -Type DWord

# Disable publishing of Win10 user activity
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "PublishUserActivities" -Value 1 -Type DWord

# Disable Win10 settings sync to cloud
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "DisableSettingSync" -Value 2 -Type DWord

# Disable the advertising ID
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Name "DisabledByGroupPolicy" -Value 1 -Type DWord

# Disable Windows GameDVR (Broadcasting and Recording)
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Name "AllowGameDVR" -Value 0 -Type DWord

# Disable Microsoft consumer experience which prevent notifications of suggested applications to install
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Value 1 -Type DWord

New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SystemPaneSuggestionsEnabled" -Value 0 -Type DWord
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SilentInstalledAppsEnabled" -Value 0 -Type DWord
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEnabled" -Value 0 -Type DWord
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "OemPreInstalledAppsEnabled" -Value 0 -Type DWord

# Disable websites accessing local language list
New-Item -Path "HKCU:\Control Panel\International\User Profile" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Control Panel\International\User Profile" -Name "HttpAcceptLanguageOptOut" -Value 1 -Type DWord

# Prevent toast notifications from appearing on lock screen
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "NoToastApplicationNotificationOnLockScreen" -Value 1 -Type DWord

###############################################################################################################
# Enable Advanced Windows Logging
###############################################################################################################

Write-Output "Enabling advanced Windows logging..."

# Enlarge Windows Event Security Log Size
wevtutil sl Security /ms:1024000
wevtutil sl Application /ms:1024000
wevtutil sl System /ms:1024000
wevtutil sl "Windows Powershell" /ms:1024000
wevtutil sl "Microsoft-Windows-PowerShell/Operational" /ms:1024000

# Record command line data in process creation events eventid 4688
New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -Type DWord

# Enabled Advanced Settings
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "SCENoApplyLegacyAuditPolicy" -Value 1 -Type DWord

# Enable PowerShell Logging
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Name "EnableModuleLogging" -Value 1 -Type DWord
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1 -Type DWord

# Enable Windows Event Detailed Logging
Auditpol /set /subcategory:"Security Group Management" /success:enable /failure:enable
Auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
Auditpol /set /subcategory:"Logoff" /success:enable /failure:disable
Auditpol /set /subcategory:"Logon" /success:enable /failure:enable 
Auditpol /set /subcategory:"Removable Storage" /success:enable /failure:enable
Auditpol /set /subcategory:"SAM" /success:disable /failure:disable
Auditpol /set /subcategory:"Filtering Platform Policy Change" /success:disable /failure:disable
Auditpol /set /subcategory:"Security State Change" /success:enable /failure:enable
Auditpol /set /subcategory:"Security System Extension" /success:enable /failure:enable
Auditpol /set /subcategory:"System Integrity" /success:enable /failure:enable

###############################################################################################################
# Remove Unnecessary Apps
###############################################################################################################

Write-Output "Removing unnecessary Windows 10 apps..."

# Uninstall common extra apps found on a lot of Win10 installs
$AppsList = @(
    "Microsoft.BingWeather"
    "Microsoft.GetHelp"
    "Microsoft.Getstarted"
    "Microsoft.Messaging"
    "Microsoft.Microsoft3DViewer"
    "Microsoft.MicrosoftOfficeHub"
    "Microsoft.MicrosoftSolitaireCollection"
    "Microsoft.MixedReality.Portal"
    "Microsoft.OneConnect"
    "Microsoft.Print3D"
    "Microsoft.Wallet"
    "Microsoft.WebMediaExtensions"
    "Microsoft.WebpImageExtension"
    "microsoft.windowscommunicationsapps"
    "Microsoft.WindowsFeedbackHub"
    "Microsoft.WindowsMaps"
    "Microsoft.WindowsSoundRecorder"
    "Microsoft.Xbox.TCUI"
    "Microsoft.XboxApp"
    "Microsoft.XboxGameOverlay"
    "Microsoft.XboxGamingOverlay"
    "Microsoft.XboxIdentityProvider"
    "Microsoft.XboxSpeechToTextOverlay"
    "Microsoft.YourPhone"
    "Microsoft.ZuneMusic"
    "Microsoft.ZuneVideo"
    "Microsoft.WindowsFeedback"
    "Windows.ContactSupport"
    "PandoraMedia"
    "AdobeSystemIncorporated.AdobePhotoshop"
    "Duolingo"
    "Microsoft.BingNews"
    "Microsoft.Office.Sway"
    "Microsoft.Advertising.Xaml"
    "Microsoft.Services.Store.Engagement"
    "ActiproSoftware"
    "EclipseManager"
    "SpotifyAB.SpotifyMusic"
    "king.com.*"
    "Microsoft.NET.Native.Framework.1.*"
    "*netflix*"
)

foreach ($App in $AppsList) {
    Get-AppxPackage -Name $App -AllUsers | Remove-AppxPackage -ErrorAction SilentlyContinue
}

# Removed Provisioned Apps
# This will prevent these apps from being reinstalled on new user first logon
$ProvisionedAppsList = @(
    "Microsoft.BingWeather"
    "Microsoft.GetHelp"
    "Microsoft.Getstarted"
    "Microsoft.MicrosoftOfficeHub"
    "Microsoft.MicrosoftSolitaireCollection"
    "Microsoft.MixedReality.Portal"
    "microsoft.windowscommunicationsapps"
    "Microsoft.WindowsFeedbackHub"
    "Microsoft.WindowsMaps"
    "Microsoft.WindowsSoundRecorder"
    "Microsoft.XboxApp"
    "Microsoft.XboxTCUI"
    "Microsoft.XboxGameOverlay"
    "Microsoft.XboxGamingOverlay"
    "Microsoft.XboxIdentityProvider"
    "Microsoft.YourPhone"
    "Microsoft.ZuneMusic"
    "Microsoft.ZuneVideo"
)

foreach ($ProvApp in $ProvisionedAppsList) {
    Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -eq $ProvApp } | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue
}

###############################################################################################################
# Adobe Reader DC STIG
###############################################################################################################

Write-Output "Configuring Adobe Reader DC security settings..."

# Create necessary registry paths
$AdobeRegPaths = @(
    "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cCloud"
    "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cDefaultLaunchURLPerms"
    "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cServices"
    "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cSharePoint"
    "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cWebmailProfiles"
    "HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cWelcomeScreen"
)

foreach ($Path in $AdobeRegPaths) {
    New-Item -Path $Path -Force | Out-Null
}

# Configure Adobe Reader settings
New-Item -Path "HKLM:\Software\Adobe\Acrobat Reader\DC\Installer" -Force | Out-Null
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

New-Item -Path "HKLM:\Software\Wow6432Node\Adobe\Acrobat Reader\DC\Installer" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\Software\Wow6432Node\Adobe\Acrobat Reader\DC\Installer" -Name "DisableMaintenance" -Value 1 -Type DWord


###############################################################################################################
# Block tools which remotely install services and configure file associations
###############################################################################################################

Write-Output "Blocking remote service installation..."
$sd = sc.exe sdshow scmanager
$sd = $sd -replace '.*:', ''
sc.exe sdset scmanager "D:(D;;GA;;;NU)$sd"

# Block remote commands 
Set-ItemProperty -Path "HKLM:\Software\Microsoft\OLE" -Name "EnableDCOM" -Value "N" -Type String

# Change file associations to protect against common ransomware and social engineering attacks
Write-Output "Changing file associations to protect against common ransomware attacks..."
cmd /c 'assoc .bat=txtfile'
cmd /c 'assoc .cmd=txtfile'
cmd /c 'assoc .chm=txtfile'
cmd /c 'assoc .hta=txtfile'
cmd /c 'assoc .jse=txtfile'
cmd /c 'assoc .js=txtfile'
cmd /c 'assoc .vbe=txtfile'
cmd /c 'assoc .vbs=txtfile'
cmd /c 'assoc .wsc=txtfile'
cmd /c 'assoc .wsf=txtfile'
cmd /c 'assoc .ws=txtfile'
cmd /c 'assoc .wsh=txtfile'
cmd /c 'assoc .scr=txtfile'
cmd /c 'assoc .url=txtfile'
cmd /c 'assoc .ps1=txtfile'
cmd /c 'assoc .iso=txtfile'
cmd /c 'assoc .reg=txtfile'
cmd /c 'assoc .wcx=txtfile'
cmd /c 'assoc .slk=txtfile'
cmd /c 'assoc .iqy=txtfile'
cmd /c 'assoc .prn=txtfile'
cmd /c 'assoc .diff=txtfile'
cmd /c 'assoc .rdg=txtfile'
cmd /c 'assoc .deploy=txtfile'
cmd /c 'assoc .msc=txtfile'
cmd /c 'assoc .application=txtfile'

# Remove potentially dangerous file associations
Remove-Item -Path "HKLM:\SOFTWARE\Classes\.devicemetadata-ms" -Force -ErrorAction SilentlyContinue
Remove-Item -Path "HKLM:\SOFTWARE\Classes\.devicemanifest-ms" -Force -ErrorAction SilentlyContinue

# Prevent Local windows wireless exploitation: the Airstrike attack
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "DontDisplayNetworkSelectionUI" -Value 1 -Type DWord

# Workaround for CoronaBlue/SMBGhost Worm exploiting CVE-2020-0796
# Disable SMBv3 compression
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "DisableCompression" -Value 1 -Type DWord

###############################################################################################################
# Windows Defender Device Guard - Exploit Guard Policies
###############################################################################################################

Write-Output "Configuring Windows Defender settings..."

# Enable Windows Defender sandboxing
[Environment]::SetEnvironmentVariable("MP_FORCE_USE_SANDBOX", "1", "Machine")

# Update signatures
& "$env:ProgramFiles\Windows Defender\MpCmdRun.exe" -SignatureUpdate

# Enable Defender signatures for Potentially Unwanted Applications (PUA)
Set-MpPreference -PUAProtection Enabled

# Enable Windows Defender periodic scanning
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows Defender" -Name "PassiveMode" -Value 2 -Type DWord

# Enable early launch antimalware driver for scan of boot-start drivers
# 3 is the default which allows good, unknown and 'bad but critical'. Recommend trying 1 for 'good and unknown' or 8 which is 'good only'
Set-ItemProperty -Path "HKCU:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch" -Name "DriverLoadPolicy" -Value 3 -Type DWord

# Stop some of the most common SMB based lateral movement techniques  
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

# Enable Controlled Folder Access
Set-MpPreference -EnableControlledFolderAccess Enabled

# Enable Cloud functionality of Windows Defender
Set-MpPreference -MAPSReporting Advanced
Set-MpPreference -SubmitSamplesConsent SendAllSamples

# Enable Defender exploit system-wide protection
Set-ProcessMitigation -System -Enable DEP,EmulateAtlThunks,BottomUp,HighEntropy,SEHOP,SEHOPTelemetry,TerminateOnError

# Enable Network protection
Set-MpPreference -EnableNetworkProtection Enabled

###############################################################################################################
# Enable exploit protection (EMET on Windows 10)
###############################################################################################################

Write-Output "Enabling exploit protection..."
$tempFile = [System.IO.Path]::GetTempFileName()
Invoke-WebRequest -Uri https://demo.wd.microsoft.com/Content/ProcessMitigation.xml -OutFile $tempFile
Set-ProcessMitigation -PolicyFilePath $tempFile
Remove-Item $tempFile

###############################################################################################################
# Harden all version of MS Office against common malspam attacks
###############################################################################################################

Write-Output "Hardening Microsoft Office settings..."

# Office 2007 (12.0)
New-Item -Path "HKCU:\SOFTWARE\Microsoft\Office\12.0\Excel\Security" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\12.0\Excel\Security" -Name "PackagerPrompt" -Value 2 -Type DWord
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\12.0\Excel\Security" -Name "VBAWarnings" -Value 4 -Type DWord
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\12.0\Excel\Security" -Name "WorkbookLinkWarnings" -Value 2 -Type DWord
New-Item -Path "HKCU:\SOFTWARE\Microsoft\Office\12.0\PowerPoint\Security" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\12.0\PowerPoint\Security" -Name "PackagerPrompt" -Value 2 -Type DWord
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\12.0\PowerPoint\Security" -Name "VBAWarnings" -Value 4 -Type DWord
New-Item -Path "HKCU:\SOFTWARE\Microsoft\Office\12.0\Word\Options\vpref" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\12.0\Word\Options\vpref" -Name "fNoCalclinksOnopen_90_1" -Value 1 -Type DWord
New-Item -Path "HKCU:\SOFTWARE\Microsoft\Office\12.0\Word\Security" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\12.0\Word\Security" -Name "PackagerPrompt" -Value 2 -Type DWord
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\12.0\Word\Security" -Name "VBAWarnings" -Value 4 -Type DWord

# Office 2010 (14.0)
New-Item -Path "HKCU:\SOFTWARE\Microsoft\Office\14.0\Excel\Options" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\14.0\Excel\Options" -Name "DontUpdateLinks" -Value 1 -Type DWord
New-Item -Path "HKCU:\SOFTWARE\Microsoft\Office\14.0\Excel\Security" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\14.0\Excel\Security" -Name "PackagerPrompt" -Value 2 -Type DWord
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\14.0\Excel\Security" -Name "VBAWarnings" -Value 4 -Type DWord
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\14.0\Excel\Security" -Name "WorkbookLinkWarnings" -Value 2 -Type DWord
New-Item -Path "HKCU:\SOFTWARE\Microsoft\Office\14.0\PowerPoint\Security" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\14.0\PowerPoint\Security" -Name "PackagerPrompt" -Value 2 -Type DWord
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\14.0\PowerPoint\Security" -Name "VBAWarnings" -Value 4 -Type DWord
New-Item -Path "HKCU:\SOFTWARE\Microsoft\Office\14.0\Word\Security" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\14.0\Word\Security" -Name "PackagerPrompt" -Value 2 -Type DWord
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\14.0\Word\Security" -Name "VBAWarnings" -Value 4 -Type DWord
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\14.0\Word\Security" -Name "AllowDDE" -Value 0 -Type DWord

# Office 2013 (15.0)
New-Item -Path "HKCU:\SOFTWARE\Microsoft\Office\15.0\Excel\Options" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\15.0\Excel\Options" -Name "DontUpdateLinks" -Value 1 -Type DWord
New-Item -Path "HKCU:\SOFTWARE\Microsoft\Office\15.0\Excel\Security" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\15.0\Excel\Security" -Name "PackagerPrompt" -Value 2 -Type DWord
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\15.0\Excel\Security" -Name "VBAWarnings" -Value 4 -Type DWord
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\15.0\Excel\Security" -Name "WorkbookLinkWarnings" -Value 2 -Type DWord
New-Item -Path "HKCU:\SOFTWARE\Microsoft\Office\15.0\PowerPoint\Security" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\15.0\PowerPoint\Security" -Name "PackagerPrompt" -Value 2 -Type DWord
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\15.0\PowerPoint\Security" -Name "VBAWarnings" -Value 4 -Type DWord
New-Item -Path "HKCU:\SOFTWARE\Microsoft\Office\15.0\Word\Security" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\15.0\Word\Security" -Name "PackagerPrompt" -Value 2 -Type DWord
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\15.0\Word\Security" -Name "VBAWarnings" -Value 4 -Type DWord
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\15.0\Word\Security" -Name "AllowDDE" -Value 0 -Type DWord

# Office 2016, 2019, 365 (16.0)
New-Item -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Excel\Options" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Excel\Options" -Name "DontUpdateLinks" -Value 1 -Type DWord
New-Item -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Excel\Security" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Excel\Security" -Name "PackagerPrompt" -Value 2 -Type DWord
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Excel\Security" -Name "VBAWarnings" -Value 4 -Type DWord
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Excel\Security" -Name "WorkbookLinkWarnings" -Value 2 -Type DWord
New-Item -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\PowerPoint\Security" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\PowerPoint\Security" -Name "PackagerPrompt" -Value 2 -Type DWord
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\PowerPoint\Security" -Name "VBAWarnings" -Value 4 -Type DWord
New-Item -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Word\Security" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Word\Security" -Name "PackagerPrompt" -Value 2 -Type DWord
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Word\Security" -Name "VBAWarnings" -Value 4 -Type DWord
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Word\Security" -Name "AllowDDE" -Value 0 -Type DWord

# Office Common Security Settings
New-Item -Path "HKCU:\SOFTWARE\Microsoft\Office\Common\Security" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\Common\Security" -Name "DisableAllActiveX" -Value 1 -Type DWord

###############################################################################################################
# General OS hardening
###############################################################################################################

Write-Output "Applying general OS hardening settings..."

# Enforce the Administrator role for adding printer drivers
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers" -Name "AddPrinterDrivers" -Value 1 -Type DWord

# Forces Installer to NOT use elevated privileges during installs by default
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name "AlwaysInstallElevated" -Value 0 -Type DWord

# Disable storing password in memory in cleartext
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential" -Value 0 -Type DWord

# Prevent Kerberos from using DES or RC4
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "DisableSmartNameResolution" -Value 1 -Type DWord
New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" -Name "DisableParallelAandAAAA" -Value 1 -Type DWord

# TCP/IP hardening
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "DisableIPSourceRouting" -Value 2 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "EnableICMPRedirect" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" -Name "DisableIPSourceRouting" -Value 2 -Type DWord

# SMB hardening
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "SMB1" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" -Name "RestrictNullSessAccess" -Value 1 -Type DWord

# UAC settings
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableVirtualization" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 2 -Type DWord

# Additional security settings
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" -Name "SaveZoneInformation" -Value 2 -Type DWord
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoDataExecutionPrevention" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoHeapTerminationOnCorruption" -Value 0 -Type DWord
New-Item -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Name "AutoConnectAllowedOEM" -Value 0 -Type DWord
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" -Name "fMinimizeConnections" -Value 1 -Type DWord

# NetBIOS over TCP/IP security
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netbt\Parameters" -Name "NoNameReleaseOnDemand" -Value 1 -Type DWord

# NTLM security
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

# WPAD hardening
New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad" -Name "WpadOverride" -Value 1 -Type DWord

# Force logoff if smart card removed - Set to "2" for logoff, set to "1" for lock
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "SCRemoveOption" -Value 2 -Type DWord

# Enable SMB/LDAP Signing
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanmanWorkStation\Parameters" -Name "RequireSecuritySignature" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanmanWorkStation\Parameters" -Name "EnableSecuritySignature" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters" -Name "RequireSecuritySignature" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters" -Name "EnableSecuritySignature" -Value 1 -Type DWord
New-Item -Path "HKLM:\System\CurrentControlSet\Services\NTDS\Parameters" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\NTDS\Parameters" -Name "LDAPServerIntegrity" -Value 2 -Type DWord
New-Item -Path "HKLM:\System\CurrentControlSet\Services\ldap" -Force | Out-Null
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

# Disable (c|w)script.exe to prevent the system from running VBS scripts
New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows Script Host\Settings" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows Script Host\Settings" -Name "Enabled" -Value 0 -Type DWord
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows Script Host\Settings" -Name "ActiveDebugging" -Value 1 -Type String
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows Script Host\Settings" -Name "DisplayLogo" -Value 1 -Type String
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows Script Host\Settings" -Name "SilentTerminate" -Value 0 -Type String
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows Script Host\Settings" -Name "UseWINSAFER" -Value 1 -Type String

# Disable IPv6
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\tcpip6\parameters" -Name "DisabledComponents" -Value 0xFF -Type DWord

###############################################################################################################
# Windows Remote Access Settings
###############################################################################################################

Write-Output "Configuring remote access settings..."

# Disable solicited remote assistance
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fAllowToGetHelp" -Value 0 -Type DWord

# Require encrypted RPC connections to Remote Desktop
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fEncryptRPCTraffic" -Value 1 -Type DWord

###############################################################################################################
# Removable Media Settings
###############################################################################################################

Write-Output "Configuring removable media settings..."

# Disable autorun/autoplay on all drives
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoAutoplayfornonVolume" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer" -Name "NoDriveTypeAutoRun" -Value 255 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoAutorun" -Value 1 -Type DWord

###############################################################################################################
# WinRM Service Configuration
###############################################################################################################

Write-Output "Configuring WinRM security settings..."

# Stop WinRM Service
Stop-Service -Name WinRM -Force
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" -Name "AllowUnencryptedTraffic" -Value 0 -Type DWord

# Disable WinRM Client Digest authentication
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" -Name "AllowDigest" -Value 0 -Type DWord
Start-Service -Name WinRM

# Disabling RPC usage from a remote asset interacting with scheduled tasks
New-Item -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Schedule" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Schedule" -Name "DisableRpcOverTcp" -Value 1 -Type DWord

# Disabling RPC usage from a remote asset interacting with services
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control" -Name "DisableRemoteScmEndpoints" -Value 1 -Type DWord

###############################################################################################################
# NetBIOS and SMB Protocol Hardening
###############################################################################################################

Write-Output "Hardening NetBIOS and SMB settings..."

# Stop NetBIOS over TCP/IP
Get-WmiObject -Class Win32_NetworkAdapterConfiguration | Where-Object { $_.TcpipNetbiosOptions -eq 0 } | ForEach-Object { $_.SetTcpipNetbios(2) }
Get-WmiObject -Class Win32_NetworkAdapterConfiguration | Where-Object { $_.TcpipNetbiosOptions -eq 1 } | ForEach-Object { $_.SetTcpipNetbios(2) }

# Disable SMBv1
Disable-WindowsOptionalFeature -Online -FeatureName smb1protocol -NoRestart
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10" -Name "Start" -Value 4 -Type DWord

# Disable PowerShellv2
Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2 -NoRestart
Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -NoRestart

###############################################################################################################
# Harden lsass to help protect against credential dumping (Mimikatz)
###############################################################################################################

Write-Output "Hardening lsass to protect against credential dumping..."

# Configures lsass.exe as a protected process and disables wdigest
# Enables delegation of non-exported credentials which enables support for Restricted Admin Mode or Remote Credential Guard
New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe" -Name "AuditLevel" -Value 8 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "DisableRestrictedAdmin" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "DisableRestrictedAdminOutboundCreds" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "Negotiate" -Value 0 -Type DWord
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation" -Name "AllowProtectedCreds" -Value 1 -Type DWord

###############################################################################################################
# Disable the ClickOnce trust prompt
###############################################################################################################

Write-Output "Disabling ClickOnce trust prompt..."

# This only partially mitigates the risk of malicious ClickOnce Apps - the ability to run the manifest is disabled, but hash retrieval is still possible
New-Item -Path "HKLM:\SOFTWARE\MICROSOFT\.NETFramework\Security\TrustManager\PromptingLevel" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\MICROSOFT\.NETFramework\Security\TrustManager\PromptingLevel" -Name "MyComputer" -Value "Disabled" -Type String
Set-ItemProperty -Path "HKLM:\SOFTWARE\MICROSOFT\.NETFramework\Security\TrustManager\PromptingLevel" -Name "LocalIntranet" -Value "Disabled" -Type String
Set-ItemProperty -Path "HKLM:\SOFTWARE\MICROSOFT\.NETFramework\Security\TrustManager\PromptingLevel" -Name "Internet" -Value "Disabled" -Type String
Set-ItemProperty -Path "HKLM:\SOFTWARE\MICROSOFT\.NETFramework\Security\TrustManager\PromptingLevel" -Name "TrustedSites" -Value "Disabled" -Type String
Set-ItemProperty -Path "HKLM:\SOFTWARE\MICROSOFT\.NETFramework\Security\TrustManager\PromptingLevel" -Name "UntrustedSites" -Value "Disabled" -Type String

###############################################################################################################
# Windows Firewall Configuration
###############################################################################################################

Write-Output "Configuring Windows Firewall..."

# Enable Windows Firewall for all profiles
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True

# Block LOLBins (Living Off The Land Binaries) from making network connections
New-NetFirewallRule -DisplayName "Block appvlp.exe netconns" -Direction Outbound -Program "C:\Program Files (x86)\Microsoft Office\root\client\AppVLP.exe" -Protocol TCP -Action Block
New-NetFirewallRule -DisplayName "Block appvlp.exe netconns 2" -Direction Outbound -Program "C:\Program Files\Microsoft Office\root\client\AppVLP.exe" -Protocol TCP -Action Block
New-NetFirewallRule -DisplayName "Block calc.exe netconns" -Direction Outbound -Program "%systemroot%\system32\calc.exe" -Protocol TCP -Action Block
New-NetFirewallRule -DisplayName "Block calc.exe netconns 2" -Direction Outbound -Program "%systemroot%\SysWOW64\calc.exe" -Protocol TCP -Action Block
New-NetFirewallRule -DisplayName "Block certutil.exe netconns" -Direction Outbound -Program "%systemroot%\system32\certutil.exe" -Protocol TCP -Action Block
New-NetFirewallRule -DisplayName "Block certutil.exe netconns 2" -Direction Outbound -Program "%systemroot%\SysWOW64\certutil.exe" -Protocol TCP -Action Block
New-NetFirewallRule -DisplayName "Block cmstp.exe netconns" -Direction Outbound -Program "%systemroot%\system32\cmstp.exe" -Protocol TCP -Action Block
New-NetFirewallRule -DisplayName "Block cmstp.exe netconns 2" -Direction Outbound -Program "%systemroot%\SysWOW64\cmstp.exe" -Protocol TCP -Action Block
New-NetFirewallRule -DisplayName "Block cscript.exe netconns" -Direction Outbound -Program "%systemroot%\system32\cscript.exe" -Protocol TCP -Action Block
New-NetFirewallRule -DisplayName "Block cscript.exe netconns 2" -Direction Outbound -Program "%systemroot%\SysWOW64\cscript.exe" -Protocol TCP -Action Block
New-NetFirewallRule -DisplayName "Block esentutl.exe netconns" -Direction Outbound -Program "%systemroot%\system32\esentutl.exe" -Protocol TCP -Action Block
New-NetFirewallRule -DisplayName "Block esentutl.exe netconns 2" -Direction Outbound -Program "%systemroot%\SysWOW64\esentutl.exe" -Protocol TCP -Action Block
New-NetFirewallRule -DisplayName "Block expand.exe netconns" -Direction Outbound -Program "%systemroot%\system32\expand.exe" -Protocol TCP -Action Block
New-NetFirewallRule -DisplayName "Block expand.exe netconns 2" -Direction Outbound -Program "%systemroot%\SysWOW64\expand.exe" -Protocol TCP -Action Block
New-NetFirewallRule -DisplayName "Block extrac32.exe netconns" -Direction Outbound -Program "%systemroot%\system32\extrac32.exe" -Protocol TCP -Action Block
New-NetFirewallRule -DisplayName "Block extrac32.exe netconns 2" -Direction Outbound -Program "%systemroot%\SysWOW64\extrac32.exe" -Protocol TCP -Action Block
New-NetFirewallRule -DisplayName "Block findstr.exe netconns" -Direction Outbound -Program "%systemroot%\system32\findstr.exe" -Protocol TCP -Action Block
New-NetFirewallRule -DisplayName "Block findstr.exe netconns 2" -Direction Outbound -Program "%systemroot%\SysWOW64\findstr.exe" -Protocol TCP -Action Block
New-NetFirewallRule -DisplayName "Block hh.exe netconns" -Direction Outbound -Program "%systemroot%\system32\hh.exe" -Protocol TCP -Action Block
New-NetFirewallRule -DisplayName "Block hh.exe netconns 2" -Direction Outbound -Program "%systemroot%\SysWOW64\hh.exe" -Protocol TCP -Action Block
New-NetFirewallRule -DisplayName "Block makecab.exe netconns" -Direction Outbound -Program "%systemroot%\system32\makecab.exe" -Protocol TCP -Action Block
New-NetFirewallRule -DisplayName "Block makecab.exe netconns 2" -Direction Outbound -Program "%systemroot%\SysWOW64\makecab.exe" -Protocol TCP -Action Block
New-NetFirewallRule -DisplayName "Block mshta.exe netconns" -Direction Outbound -Program "%systemroot%\system32\mshta.exe" -Protocol TCP -Action Block
New-NetFirewallRule -DisplayName "Block mshta.exe netconns 2" -Direction Outbound -Program "%systemroot%\SysWOW64\mshta.exe" -Protocol TCP -Action Block
New-NetFirewallRule -DisplayName "Block msiexec.exe netconns" -Direction Outbound -Program "%systemroot%\system32\msiexec.exe" -Protocol TCP -Action Block
New-NetFirewallRule -DisplayName "Block msiexec.exe netconns 2" -Direction Outbound -Program "%systemroot%\SysWOW64\msiexec.exe" -Protocol TCP -Action Block
New-NetFirewallRule -DisplayName "Block nltest.exe netconns" -Direction Outbound -Program "%systemroot%\system32\nltest.exe" -Protocol TCP -Action Block
New-NetFirewallRule -DisplayName "Block nltest.exe netconns 2" -Direction Outbound -Program "%systemroot%\SysWOW64\nltest.exe" -Protocol TCP -Action Block
New-NetFirewallRule -DisplayName "Block Notepad.exe netconns" -Direction Outbound -Program "%systemroot%\system32\notepad.exe" -Protocol TCP -Action Block
New-NetFirewallRule -DisplayName "Block Notepad.exe netconns 2" -Direction Outbound -Program "%systemroot%\SysWOW64\notepad.exe" -Protocol TCP -Action Block
New-NetFirewallRule -DisplayName "Block odbcconf.exe netconns" -Direction Outbound -Program "%systemroot%\system32\odbcconf.exe" -Protocol TCP -Action Block
New-NetFirewallRule -DisplayName "Block odbcconf.exe netconns 2" -Direction Outbound -Program "%systemroot%\SysWOW64\odbcconf.exe" -Protocol TCP -Action Block
New-NetFirewallRule -DisplayName "Block pcalua.exe netconns" -Direction Outbound -Program "%systemroot%\system32\pcalua.exe" -Protocol TCP -Action Block
New-NetFirewallRule -DisplayName "Block pcalua.exe netconns 2" -Direction Outbound -Program "%systemroot%\SysWOW64\pcalua.exe" -Protocol TCP -Action Block
New-NetFirewallRule -DisplayName "Block regasm.exe netconns" -Direction Outbound -Program "%systemroot%\system32\regasm.exe" -Protocol TCP -Action Block
New-NetFirewallRule -DisplayName "Block regasm.exe netconns 2" -Direction Outbound -Program "%systemroot%\SysWOW64\regasm.exe" -Protocol TCP -Action Block
New-NetFirewallRule -DisplayName "Block regsvr32.exe netconns" -Direction Outbound -Program "%systemroot%\system32\regsvr32.exe" -Protocol TCP -Action Block
New-NetFirewallRule -DisplayName "Block regsvr32.exe netconns 2" -Direction Outbound -Program "%systemroot%\SysWOW64\regsvr32.exe" -Protocol TCP -Action Block
New-NetFirewallRule -DisplayName "Block replace.exe netconns" -Direction Outbound -Program "%systemroot%\system32\replace.exe" -Protocol TCP -Action Block
New-NetFirewallRule -DisplayName "Block replace.exe netconns 2" -Direction Outbound -Program "%systemroot%\SysWOW64\replace.exe" -Protocol TCP -Action Block
New-NetFirewallRule -DisplayName "Block rpcping.exe netconns" -Direction Outbound -Program "%systemroot%\SysWOW64\rpcping.exe" -Protocol TCP -Action Block
New-NetFirewallRule -DisplayName "Block rundll32.exe netconns" -Direction Outbound -Program "%systemroot%\system32\rundll32.exe" -Protocol TCP -Action Block
New-NetFirewallRule -DisplayName "Block rundll32.exe netconns 2" -Direction Outbound -Program "%systemroot%\SysWOW64\rundll32.exe" -Protocol TCP -Action Block
New-NetFirewallRule -DisplayName "Block runscripthelper.exe netconns" -Direction Outbound -Program "%systemroot%\system32\runscripthelper.exe" -Protocol TCP -Action Block
New-NetFirewallRule -DisplayName "Block runscripthelper.exe netconns 2" -Direction Outbound -Program "%systemroot%\SysWOW64\runscripthelper.exe" -Protocol TCP -Action Block
New-NetFirewallRule -DisplayName "Block scriptrunner.exe netconns" -Direction Outbound -Program "%systemroot%\system32\scriptrunner.exe" -Protocol TCP -Action Block
New-NetFirewallRule -DisplayName "Block scriptrunner.exe netconns 2" -Direction Outbound -Program "%systemroot%\SysWOW64\scriptrunner.exe" -Protocol TCP -Action Block
New-NetFirewallRule -DisplayName "Block SyncAppvPublishingServer.exe netconns" -Direction Outbound -Program "%systemroot%\system32\SyncAppvPublishingServer.exe" -Protocol TCP -Action Block
New-NetFirewallRule -DisplayName "Block SyncAppvPublishingServer.exe netconns 2" -Direction Outbound -Program "%systemroot%\SysWOW64\SyncAppvPublishingServer.exe" -Protocol TCP -Action Block
New-NetFirewallRule -DisplayName "Block wmic.exe netconns" -Direction Outbound -Program "%systemroot%\system32\wbem\wmic.exe" -Protocol TCP -Action Block
New-NetFirewallRule -DisplayName "Block wmic.exe netconns 2" -Direction Outbound -Program "%systemroot%\SysWOW64\wbem\wmic.exe" -Protocol TCP -Action Block
New-NetFirewallRule -DisplayName "Block wscript.exe netconns" -Direction Outbound -Program "%systemroot%\system32\wscript.exe" -Protocol TCP -Action Block
New-NetFirewallRule -DisplayName "Block wscript.exe netconns 2" -Direction Outbound -Program "%systemroot%\SysWOW64\wscript.exe" -Protocol TCP -Action Block

# Disable TCP timestamps
netsh int tcp set global timestamps=disabled

# Enable Firewall Logging
Set-NetFirewallProfile -Profile Domain,Public,Private -LogFileName "%systemroot%\system32\LogFiles\Firewall\pfirewall.log" -LogMaxSizeKilobytes 4096 -LogBlocked True -LogAllowed False

###############################################################################################################
# Disable AutoRun and show known file extensions
###############################################################################################################

Write-Output "Disabling AutoRun and showing known file extensions..."

# Disable AutoRun
New-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Value 0xff -Type DWord
New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Value 0xff -Type DWord

# Show known file extensions and hidden files
New-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Value 0 -Type DWord
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -Value 1 -Type DWord
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowSuperHidden" -Value 1 -Type DWord
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowSuperHidden" -Value 1 -Type DWord

# Disable 8.3 names (Mitigate Microsoft IIS tilde directory enumeration) and Last Access timestamp
fsutil behavior set disable8dot3 1
fsutil behavior set disablelastaccess 0

###############################################################################################################
# Biometrics Security Settings
###############################################################################################################

Write-Output "Configuring biometrics security settings..."

# Enable anti-spoofing for facial recognition
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures" -Name "EnhancedAntiSpoofing" -Value 1 -Type DWord

# Disable other camera use while screen is locked
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" -Name "NoLockScreenCamera" -Value 1 -Type DWord

# Prevent Windows app voice activation while locked
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsActivateWithVoiceAboveLock" -Value 2 -Type DWord

# Prevent Windows app voice activation entirely (be mindful of those with accessibility needs)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsActivateWithVoice" -Value 2 -Type DWord

###############################################################################################################
# Disable weak TLS/SSL ciphers and protocols
###############################################################################################################

Write-Output "Disabling weak TLS/SSL ciphers and protocols..."

# Encryption - Ciphers: AES only
New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\AES 128/128" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\AES 128/128" -Name "Enabled" -Value 0xffffffff -Type DWord
New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\AES 256/256" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\AES 256/256" -Name "Enabled" -Value 0xffffffff -Type DWord
New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\DES 56/56" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\DES 56/56" -Name "Enabled" -Value 0 -Type DWord
New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\NULL" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\NULL" -Name "Enabled" -Value 0 -Type DWord
New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 128/128" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 128/128" -Name "Enabled" -Value 0 -Type DWord
New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 40/128" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 40/128" -Name "Enabled" -Value 0 -Type DWord
New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 56/128" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 56/128" -Name "Enabled" -Value 0 -Type DWord
New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 128/128" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 128/128" -Name "Enabled" -Value 0 -Type DWord
New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 40/128" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 40/128" -Name "Enabled" -Value 0 -Type DWord
New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 56/128" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 56/128" -Name "Enabled" -Value 0 -Type DWord
New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 64/128" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 64/128" -Name "Enabled" -Value 0 -Type DWord
New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 168" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 168" -Name "Enabled" -Value 0 -Type DWord

# Encryption - Hashes: All allowed
New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\MD5" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\MD5" -Name "Enabled" -Value 0xffffffff -Type DWord
New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA" -Name "Enabled" -Value 0xffffffff -Type DWord
New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA256" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA256" -Name "Enabled" -Value 0xffffffff -Type DWord
New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA384" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA384" -Name "Enabled" -Value 0xffffffff -Type DWord
New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA512" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA512" -Name "Enabled" -Value 0xffffffff -Type DWord

# Create the Diffie-Hellman key path if it doesn't exist
New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman" -Force | Out-Null
# Enable Diffie-Hellman and set minimum key bit length
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman" -Name "Enabled" -Value 0xffffffff -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman" -Name "ServerMinKeyBitLength" -Value 0x00001000 -Type DWord

# Create and enable ECDH key exchange
New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\ECDH" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\ECDH" -Name "Enabled" -Value 0xffffffff -Type DWord

# Create and enable PKCS key exchange
New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\PKCS" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\PKCS" -Name "Enabled" -Value 0xffffffff -Type DWord

###############################################################################################################
# Encryption - Protocols: TLS 1.0 and higher (recommended options)
###############################################################################################################

Write-Output "Configuring SSL/TLS protocols..."

# Multi-Protocol Unified Hello - Disable
New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Client" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Client" -Name "Enabled" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Client" -Name "DisabledByDefault" -Value 1 -Type DWord

New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Server" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Server" -Name "Enabled" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\Multi-Protocol Unified Hello\Server" -Name "DisabledByDefault" -Value 1 -Type DWord

# PCT 1.0 - Disable
New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Client" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Client" -Name "Enabled" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Client" -Name "DisabledByDefault" -Value 1 -Type DWord

New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Server" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Server" -Name "Enabled" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Server" -Name "DisabledByDefault" -Value 1 -Type DWord

# SSL 2.0 - Disable
New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client" -Name "Enabled" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client" -Name "DisabledByDefault" -Value 1 -Type DWord

New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server" -Name "Enabled" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server" -Name "DisabledByDefault" -Value 1 -Type DWord

# SSL 3.0 - Disable
New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client" -Name "Enabled" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client" -Name "DisabledByDefault" -Value 1 -Type DWord

New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server" -Name "Enabled" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server" -Name "DisabledByDefault" -Value 1 -Type DWord

# TLS 1.0 - Enable
New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client" -Name "Enabled" -Value 0xffffffff -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client" -Name "DisabledByDefault" -Value 0 -Type DWord

New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" -Name "Enabled" -Value 0xffffffff -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" -Name "DisabledByDefault" -Value 0 -Type DWord

# TLS 1.1 - Enable
New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client" -Name "Enabled" -Value 0xffffffff -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client" -Name "DisabledByDefault" -Value 0 -Type DWord

New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" -Name "Enabled" -Value 0xffffffff -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" -Name "DisabledByDefault" -Value 0 -Type DWord

# TLS 1.2 - Enable
New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client" -Name "Enabled" -Value 0xffffffff -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client" -Name "DisabledByDefault" -Value 0 -Type DWord

New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" -Name "Enabled" -Value 0xffffffff -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" -Name "DisabledByDefault" -Value 0 -Type DWord

Write-Output "TLS/SSL protocol configuration complete."

###############################################################################################################
# Verify and enforce device driver signing
###############################################################################################################

Write-Output "Enforcing device driver signing..."

BCDEDIT /set nointegritychecks OFF

###############################################################################################################
# Display completion message
###############################################################################################################

Write-Output "`nWindows 10 security hardening script completed."
Write-Output "It is recommended to restart your computer for all settings to take effect."
SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" -Name "SystemRestorePointCreationFrequency" -Value 20 -Type DWord
Checkpoint-Computer -Description "BeforeSecurityHardening" -RestorePointType "MODIFY_SETTINGS"