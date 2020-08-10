<# 
Written by dr-angel
Ver 1.2
Config file must be included in script root directory
Download and signature check courtesy of michael mccool, datto community. 
#>

$downLink = "https://live.sysinternals.com/sysmon.exe"

# Functions from here 

# Download using TLS1.2
function downloadFile ($url, $whitelist) {
    [Net.ServicePointManager]::SecurityProtocol = [Enum]::ToObject([Net.SecurityProtocolType], 3072)
    write-host "- Downloading $url..."
    (New-Object System.Net.WebClient).DownloadFile("$url","sysmon.exe")
    if (!(test-path "sysmon.exe")) {
        write-host "- ERROR: File sysmon.exe could not be downloaded."
        write-host "  Please ensure you are whitelisting $whitelist."
        write-host "- Operations cannot continue; exiting."
        exit 1
    } else {
        write-host "- Downloaded Sysmon"
    }
}

# Verify signing certificate
function verifyPackage ($file, $certificate, $thumbprint, $name, $url) {
    $varChain = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Chain
    try {
        $varChain.Build((Get-AuthenticodeSignature -FilePath "$file").SignerCertificate) | out-null
    } catch [System.Management.Automation.MethodInvocationException] {
        write-host "- ERROR: $name installer did not contain a valid digital certificate."
        write-host "  This could suggest a change in the way $name is packaged; it could"
        write-host "  also suggest tampering in the connection chain."
        write-host "- Please ensure $url is whitelisted and try again."
       write-host "  If this issue persists across different devices, please file a support ticket."
    }

    $varIntermediate=($varChain.ChainElements | ForEach-Object {$_.Certificate} | Where-Object {$_.Subject -match "$certificate"}).Thumbprint

    if ($varIntermediate -ne $thumbprint) {
        write-host "- ERROR: $file did not pass verification checks for its digital signature."
        write-host "  This could suggest that the certificate used to sign the $name installer"
        write-host "  has changed; it could also suggest tampering in the connection chain."
        write-host `r
        if ($varIntermediate) {
            write-host ": We received: $varIntermediate"
            write-host "  We expected: $thumbprint"
            write-host "  Please report this issue."
        }
        write-host "- Installation cannot continue. Exiting."
        exit 1
    } else {
        write-host "- Digital Signature verification passed."
    }
}

# Verify service running and OK
function checkService ($serviceName, $serviceStatus) {
    Get-Service $serviceName | ForEach-Object {
        if ($_.status -eq "$serviceStatus") {
            write-host "$serviceName successfully installed and running. Exiting."
            }
        else {
            write-host "$serviceName not running, please check service exists or try again."
            exit 1
        }
    }
}

# And now jigsaws fall into place

downloadFile $downLink "https://live.sysinternals.com"
verifyPackage "sysmon.exe" "Microsoft Code Signing PCA 2011" "F252E794FE438E35ACE6E53762C0A234A2C52135" "Sysmon" "https://live.sysinternals.com"
.\sysmon.exe /accepteula -i .\sysmonconfig.xml # Comment out config if you wish to use the default sysmon config
checkService "Sysmon" "Running"

# Increasing log size to 2GB... let's not over do it.
write-host "`n- Increasing sysmon log size to 2GB..."
reg add HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Sysmon/Operational /v MaxSize /t REG_DWORD /d 0x7a120000 /f
if ($?) {
    write-host "`n- sysmon logs grew!"
}
else {
    write-host "`n- sysmon logs size change failed."
    exit 1
}

# Finally, hide the sysmon service from... sneaky sneaky
write-host "`n- Hiding sysmon service from Services MicrosoftTM Management Console..."
cmd.exe /c "sc sdset Sysmon D:(D;;DCLCWPDTSD;;;IU)(D;;DCLCWPDTSD;;;SU)(D;;DCLCWPDTSD;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD) || echo. && echo '- hiding sysmon service successfully failed. Exiting.' && exit 1"
write-host "`n- Sysmon service successfully hidden. Have a good day."
