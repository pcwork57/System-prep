#package needs to be .ps1
#choco install boxstarter
#powershell -NoProfile -ExecutionPolicy bypass -command "Import-Module '%~dp0Boxstarter.Chocolatey\Boxstarter.Chocolatey.psd1';Invoke-ChocolateyBoxstarter %*"
#to run from boxstarter command line with reboot
#$cred=Get-Credential domain\username
#Install-BoxstarterPackage -PackageName "MyPackage1","MyPackage2" -Credential $cred


Install-WindowsUpdate -AcceptEula -full
if (Test-PendingReboot) { Invoke-Reboot }

choco install googlechrome
choco install powershell

if (Test-PendingReboot) { Invoke-Reboot }
