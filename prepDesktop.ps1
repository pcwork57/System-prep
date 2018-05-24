#link to install boxstarter & this script
#START https://boxstarter.org/package/nr/url?https://raw.githubusercontent.com/pcwork57/System-prep/master/prepDesktop.ps1
#allow reboot
#START https://boxstarter.org/package/url?https://raw.githubusercontent.com/pcwork57/System-prep/master/prepDesktop.ps1
#
$env:PSExecutionPolicyPreference = "remotesigned"
#$env:ErrorActionPreference = "Continue"
#$ErrorActionPreference = "SilentlyContinue"
#######download lantrx desktop scrips########################
iex ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/pcwork57/System-prep/master/lantrxdesktop.ps1'))
#install-lantrxonlinescripts -desktop
write-output "setting all users profile for lantrx desktop"
powershell {iex ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/pcwork57/System-prep/master/lantrxdesktop.ps1'));install-lantrxonlinescripts -desktop} > null

#######install package managers########################

write-output "setting execution policy remotesigned"
powershell {set-ExecutionPolicy remotesigned -Force}
write-output "installing boxtstarter"
powershell {if(!(Test-Path "C:\ProgramData\Boxstarter\BoxstarterShell.ps1")){iex ((New-Object System.Net.WebClient).DownloadString('http://help.lantrxinc.com/powershell/bootstrapper.ps1')); get-boxstarter -Force}}
write-output "installing chocolatey"
powershell {if(!(Test-Path "C:\ProgramData\chocolatey\choco.exe")){iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))}}

if (Test-PendingReboot) { Invoke-Reboot }
write-output "pending reboot: $(Test-PendingReboot)"

#remove-item "C:\Users\Public\desktop\Boxstarter Shell.lnk" -force

#setup windows explorer to show file extenstions
Set-WindowsExplorerOptions -EnableShowFileExtension

#setup lantrx package repository
write-output "setting lantrx package repository"
choco source remove -n=lantrx-depo
choco source add -n=lantrx-depo -s "'http://nupkg.lantrxinc.com/repository/App_Depo/'"

#install function for removal of HP software

if(!(test-path -path "c:\temp\remove.csv")){
new-item -path c:\ -name temp -itemtype directory
New-Item -Path c:\temp\remove.csv -Type file -force -Value (New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/pcwork57/System-prep/master/remove.csv')
New-Item -Path c:\temp\install.csv -Type file -force -Value (New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/pcwork57/System-prep/master/install.csv')
New-Item -path c:\temp\packages.config -type file -force -value (New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/pcwork57/System-prep/master/packages.xml')

install-desktop -remove -csvfile c:\temp\remove.csv -verbose
install-desktop -install -csvfile c:\temp\install.csv -verbose
}

if (Test-PendingReboot) { Invoke-Reboot }

#install preset packages
#choco install -y c:\temp\packages.config
#choco install -y googlechrome --ignore-checksum
#choco install -y 7zip.install --ignore-checksum

#clean up download files
remove-item c:\temp\packages.config
remove-item c:\temp\remove.csv
remove-item c:\temp\install.csv

#clean up desktop
Remove-Item C:\Users\Public\Desktop\Skype*.lnk -Force
Remove-Item 'C:\Users\Public\Desktop\HP Touchpoint*.lnk' -force

if (Test-PendingReboot) { Invoke-Reboot }

write-output "scrubing windows 10"
Start-Process -FilePath "powershell" -ArgumentList '{clean-win10scrub;Start-Sleep -Seconds 20}' -WindowStyle Normal
#clean-win10scrub
#powershell {clean-win10scrub}

write-output "clearing start menu"
powershell {Clean-win10startmenu}

if (Test-PendingReboot) { Invoke-Reboot }