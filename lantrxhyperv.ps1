Write-Output "!!!! Importing Lantrx PowerShell Hyper-V Scrips !!!!"
iex ((New-Object System.Net.WebClient).DownloadString('http://help.lantrxinc.com/powershell/lantrx-bootstrap.ps1'))

#preps a new blank drive for backups
function new-backupdrive {
$name = [guid]::NewGuid()
$name = $name.ToString() -replace ('-', '')
$name = $name.Substring(0, 32) #max for ntfs volume lable


#$driveletter='B'
#$name=$name +(get-date).year.ToString()
#$name=$name + (get-date).month.ToString()
#$name=$name + (get-date).day.ToString()
#if(!(Test-Path variable:id)){$id=0}
$disks = Get-Disk | Where partitionstyle -eq "raw"
foreach($disk in $disks){
$id++
$no=$disk|Initialize-Disk -PartitionStyle MBR -PassThru | New-Partition -AssignDriveLetter -UseMaximumSize | Format-Volume -FileSystem NTFS -NewFileSystemLabel "$name" -Confirm:$false
$no
#$disk | Get-Partition | Set-Partition -NewDriveLetter $driveletter
#Get-Volume -DriveLetter $driveletter
}
}

write-output "!!!! Finished installing scripts from Lantrx !!!!"
