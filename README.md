# System-prep
used to standardize prep desktop & server

################################################
Notes:
Open powershell with adminrights and past line into shell to add functions


online Desktop Prep:

iex ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/pcwork57/System-prep/rebrand/onlinebootstrap.ps1'))
iex ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/pcwork57/System-prep/rebrand/prepDesktop.ps1'))

Download online scrips based on os version:
iex ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/pcwork57/System-prep/rebrand/onlinedesktop.ps1'))
iex ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/pcwork57/System-prep/rebrand/onlinehyperv.ps1'))
iex ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/pcwork57/System-prep/rebrand/onlineserver.ps1'))

iex ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/pcwork57/System-prep/rebrand/onlineexchange.ps1'))

Package Install ONLY:
iex ((New-Object System.Net.WebClient).DownloadString('https://boxstarter.org/bootstrapper.ps1')); get-boxstarter -Force
iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))

t.txt

for local testing
iex ((New-Object System.Net.WebClient).DownloadString('http://help.lantrxinc.com/powershell/testing/lantrxdesktop.ps1'))
##################################################

t.txt:
#https://www.tenforums.com/tutorials/4689-uninstall-apps-windows-10-a.html
Get-AppXPackage | where-object {$_.name –notlike “*store*”} | Remove-AppxPackage

#remove fro you current account
Get-AppXPackage | where-object {$_.name –notlike “*store*”} | Remove-AppxPackage

#remove all apps from new accoutns
Get-appxprovisionedpackage –online | where-object {$_.packagename –notlike “*store*”} | Remove-AppxProvisionedPackage -online

#remove all apps from all current accounts on pc
Get-AppxPackage -AllUsers | where-object {$_.name –notlike “*store*”} | Remove-AppxPackage
