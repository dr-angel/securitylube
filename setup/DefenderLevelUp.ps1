<# This is a script to quickly improve protection offered by Windows Defender.

Ver 1.1
Written by dr-angel

Shamelessly based on article by Jackson Van Dyke at https://jacksonvd.com/levelling-up-windows-defender/
All commands documented by MS in KB.

Using the Get-MpPreference command will reveal Defender settings, however configured results won't be plain English. Instead a number is assigned to the settings value. I'll try to include the related number value for these settings.

To do:
- Enable Firewall if off
- Enable Tamper Protection if running 1909+. It's probably on anyway.
#>

# First, we make sure you are taking your medicine
$OSbuild = ([Environment]::OSVersion).Version.Build

if ($OSbuild -lt 17763) {
    write-host "- Your Windows is behind on updates. Microsoft stops releasing Security Updates for older versions of Windows."
    Start-Sleep 3
    write-host "- Sorry for the bad news."
    Start-Sleep 2
    write-host "- Please go to Start Menu > Settings > Update and Security > Upgrade to version 1809 (or higher), and then run this script again after the upgrade."
    $consent = read-host "- Alternatively, type 'Yes' and hit enter to attempt to continue"
    if ($consent -like "yes") {break}
    Write-host "- Exiting..."
    Start-Sleep 1
    exit
}

<# Enable MAPS - in GPO go to Computer configuration -> Administrative templates -> Windows Components -> Microsoft Defender Antivirus -> MAPS.
The “Join Microsoft MAPS” setting should be configured as Enabled with either Basic or Advanced membership (the distinction does not matter on Windows 10 systems). The “Send file samples when further analysis is required” setting should be set to either Send safe samples or Send all samples, depending on your individual requirements.
#>
write-host "- Enabling MAPS..."
Set-MpPreference -MAPSReporting Advanced # 2 = Advanced, this is the default
Set-MpPreference -SubmitSamplesConsent 1 # AlwaysPrompt = 0, SendSafeSamples = 1, Send all samples = 3, WeDontTalkAboutThisOne = 2
if ($?) {write-host "- Done."} else {write-host "- Sorry, something went wrong."} # If MAPS fails to set, only God can help you.

# Real-time cloud-based detection can be enabled through Computer configuration -> Administrative templates -> Windows Components -> Microsoft Defender Antivirus -> MAPS, by setting the “Configure the ‘Block at First Sight’ feature” setting to Enabled. 
write-host "- And now Block At First Sight..."
Set-MpPreference -CloudBlockLevel Moderate # Moderate is Default (1) and least likely to flag false positives. High = 2
Set-MpPreference -DisableBlockAtFirstSeen $False
Set-MpPreference -CloudExtendedTimeout 20 # At this level, block at first sight will prevent execution of unknown suspect executables for 30 seconds (Default 10s + 20s)
cmd /c ""%ProgramFiles%\Windows Defender\MpCmdRun.exe" -validatemapsconnection"
if ($?) {write-host "- Done."} else {write-host "- Sorry, something went wrong."}

# Enable detection of Potentially Unwanted Applications
write-host "- Allowing detection of PUAs..."
Set-MpPreference -PUAProtection 1 -ErrorAction Stop
write-host "- Done."

<# https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/enable-network-protection
Network protection helps to prevent employees from using any application to access dangerous domains that may host phishing scams, exploits, and other malicious content on the Internet. You can audit network protection in a test environment to see which apps would be blocked before you enable it.
Applicable for Windows 10 Pro+
#>
$winversion = systeminfo | findstr /B /C:"OS Name"

if (($winversion -like "*Pro") -or ($winversion -like "*Enterprise")){
    write-host "- Blocking dangerous domains - ones that contain phishing, scams, exploits etc..."
    Set-MpPreference -EnableNetworkProtection Enable -ErrorAction Stop # Optionally use "AuditMode" to log events only. AuditMode = 0, Enable = 1
    write-host "- Done."
} else {
    write-host "- Sorry, unless you have Windows 10 Pro or Enterprise, this script is unable to help you any further..."
    Start-Sleep 2
    pause
    exit
}

<# https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/attack-surface-reduction
Attack surface reduction rules can be enabled via Computer configuration -> Administrative templates -> Windows Components -> Microsoft Defender Antivirus -> Windows Defender Exploit Guard -> Attack Surface Reduction.
Only valid for Windows 10 Enterprise 1703+
This rule has all current 15 ASR rules applied
#>

# Check we are running Enterprise or this does nothing
write-host "- Applying Attack Surface Reduction rules..."
if ($winversion -like "*Enterprise") {
    write-host " Enterprise SKU detected... Running"
    Set-MpPreference -AttackSurfaceReductionRules_Ids BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550,D4F940AB-401B-4EFC-AADC-AD5F3C50688A,3B576869-A4EC-4529-8536-B80A7769E899,75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84,D3E037E1-3EB8-44C8-A917-57927947596D,5BEB7EFE-FD9A-4556-801D-275E5FFC04CC,92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B,01443614-cd74-433a-b99e-2ecdc07bfc25,c1db55ab-c21a-4637-bb3f-a12568109d35,9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2,d1e49aac-8f56-4280-b9ba-993a6d77406c,b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4,26190899-1602-49e8-8b27-eb1d0a1ce869,7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c -AttackSurfaceReductionRules_Actions Enabled,Enabled,Enabled,Enabled,Enabled,Enabled,Enabled,Enabled,Enabled,Enabled,Enabled,Enabled,Enabled,Enabled -ErrorAction Stop
    if ($OSbuild -ge 18362) {
        Add-MpPreference -AttackSurfaceReductionRules_Ids e6db77e5-3df2-4cf1-b95a-636979351e5b -AttackSurfaceReductionRules_Actions Enabled
    }
    write-host "- The following ASR rules have been applied:"
    $(Get-MpPreference).AttackSurfaceReductionRules_Ids
    write-host "`n- All done. You can now close this. Stay safe."
} else { 
    write-host "`n- Sorry, not running Enterprise SKU. Cannot apply ASR rules. You can now close this."
}
