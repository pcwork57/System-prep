Install-WindowsUpdate -AcceptEula -full
if (Test-PendingReboot) { Invoke-Reboot }

choco install googlechrome
choco install powershell

if (Test-PendingReboot) { Invoke-Reboot }
