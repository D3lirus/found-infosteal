# found-infosteal
This is a repository of files associated with an info-stealer I found in my own system. It had a scheduled task, that would every 30s attempt to send stolen data to an endpoint on the domain `activatorcounter.com`.<br />
The order of execution was as such: 
1. scheduler
2. invoke-from-env.ps1
3. invoke-from-registry.ps1
4. invoke-from-remote.ps1
5. info-stealer service
