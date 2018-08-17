#need to check if windows 7 OR server 2008r2 (no sp1)
#if not install 
#choco install -y kb976932
#version 6.1* is server 2008r2
#CSDVersion "Service Pack 1"
#kb976932 is sp1 for windows 7 & server 2008r2
$osversion = GET-WMIOBJECT win32_operatingsystem
if ($osversion.Version -like "6.1*"){
if ($osversion.ServicePackMajorVersion -eq 0){
"NO service pack - installed service pack 1"
choco install -y kb976932
choco install -y dotnet4.5
}#end sp check
}#end os version
if (Test-PendingReboot) { Invoke-Reboot }

Install-WindowsUpdate -AcceptEula #-getUpdatesFromMS
if (Test-PendingReboot) { Invoke-Reboot }

choco install -y powershell

if (Test-PendingReboot) { Invoke-Reboot }

Enable-RemoteDesktop -DoNotRequireUserLevelAuthentication