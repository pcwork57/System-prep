Write-Output "!!!! Importing Lantrx PowerShell Server Scrips !!!!"
iex ((New-Object System.Net.WebClient).DownloadString('http://help.lantrxinc.com/powershell/lantrx-bootstrap.ps1'))
#connects to exchange powershell from another admin system
function connect-ADexchange{
    <#
    .Synopsis
       Connects to exchange server in current domain uses current login credentials
    .DESCRIPTION
       Connects to the Exchange server config and imports the exchange modules
       this allows you to run exchange commands from an admin workstations OR another server
    .EXAMPLE
       Automaticly find and connect to the exchange server
       connect-exchange
    .EXAMPLE
       specify the exchange server computer name you want to connect to 
       connect-exchange -computername exchange
    #>
    
        [CmdletBinding()]
        [OutputType([Boolean])]
        Param
        (
            # exchange server netbios name
            [string]$Computername
        )
    
        Begin
        {
        }#end begin
        Process
        {
            if(!$Computername){
            Write-Verbose "getting domain"
            $domain = ($env:USERDNSDOMAIN).split(".")
            Write-Verbose "getting exchange info from ldap"
            $ldap = "LDAP://"+$domain[0]+"."+$domain[1]+"/CN=Exchange Servers,OU=Microsoft Exchange Security Groups,DC="+$domain[0]+",DC="+$domain[1]
            $exchangeServers = [ADSI]$ldap
            foreach($s in $exchangeServers.Member){
                $server=$s.split(",")
                $server=$server[0].substring(3,$server[0].length-3)
                Write-Verbose "attempting to connect to exchange server $server"
                if(!($exsession)){
                    try{
                        Write-Output "attempting to connect to exchange server $server aquired from AD"
                        $exsession = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri "http://$server/powershell"
                        Import-PSSession $exsession > $null
                    }catch{}
                }#end if
            }#end foreach

            }else{
            if(!($exsession)){
                try{
                    Write-Verbose "use provided computer name $computername"
                    Write-Output "attempting to connect to exchange server $computername aquired from AD"
                    $exsession = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri "http://$computername/powershell"
                    Import-PSSession $exsession > $null
                }catch{}
            
            }#end if exsess
            }#end else
        }#end process
        End
        {
        }#end end
    }

#pulls login info from current server
function get-logins{
<#
.Synopsis
   Get login info from security log of localhost
.DESCRIPTION
   reads in event ID 4624 for user login's and get user and ip and time of user login over the last 8 hours a max of 1000 entries
   tested on v2 & v4
.EXAMPLE
   get-logins
.EXAMPLE
   $ips = get-logins | group loginipaddress
.EXAMPLE
   get-logins | select LoginUserName,loginipaddress | group LoginUserName
#>
    $date = (get-date).AddHours(-8)
    $Events = Get-WinEvent -FilterHashtable @{Logname='Security';Id=4624;starttime=$date} -MaxEvents 1000

    foreach ($Event in $Events) {
        $EventXML = [XML]$Event.ToXML()
		
		if( !($EventXML.Event.EventData.Data[5]."#text".Contains("$")) -and !($EventXML.event.eventdata.data[6]."#text".Contains("NT AUTHORITY")) ){
        $properties = @{
                        #'LoginUserName' = $EventXML.event.eventdata.data."#text"[5]; #does not work on PSv2
						'LoginUserName' = $EventXML.event.eventdata.data[5]."#text";
                        #'LoginDomainName' = $EventXML.event.eventdata.data."#text"[6]; #does not work on PSv2
						'LoginDomainName' = $EventXML.event.eventdata.data[6]."#text";
                        #'LoginIPAddress' = $EventXML.event.eventdata.data."#text"[18]; #does not work on PSv2
						'LoginIPAddress' = $EventXML.event.eventdata.data[18]."#text";
                        'DateTime' = $Event.TimeCreated
                        }
        $userinfo=New-Object -TypeName psobject -Property $properties
        Write-Output $userinfo
		}
    }
}

#pulls failed login info from current server
function get-loginsfailed{
<#
.Synopsis
   Get login info from security log of localhost
.DESCRIPTION
   reads in event ID 4625 for user login's and get user and ip and time of user login over the last 8 hours a max of 1000 entries
   tested on v2 & v4
.EXAMPLE
   get-logins
.EXAMPLE
   $ips = get-logins | group loginipaddress
.EXAMPLE
   get-logins | select LoginUserName,loginipaddress | group LoginUserName
#>
    $date = (get-date).AddHours(-8)
    $Events = Get-WinEvent -FilterHashtable @{Logname='Security';Id=4625;starttime=$date} -MaxEvents 1000

    foreach ($Event in $Events) {
        $EventXML = [XML]$Event.ToXML()
		
		if( !($EventXML.Event.EventData.Data[5]."#text".Contains("$")) -and !($EventXML.event.eventdata.data[6]."#text".Contains("NT AUTHORITY")) ){
        $properties = @{
                        #'LoginUserName' = $EventXML.event.eventdata.data."#text"[5]; #does not work on PSv2
						'LoginUserName' = $EventXML.event.eventdata.data[5]."#text";
                        #'LoginDomainName' = $EventXML.event.eventdata.data."#text"[6]; #does not work on PSv2
						'LoginDomainName' = $EventXML.event.eventdata.data[6]."#text";
                        #'LoginIPAddress' = $EventXML.event.eventdata.data."#text"[18]; #does not work on PSv2
						'LoginIPAddress' = $EventXML.event.eventdata.data[18]."#text";
                        'DateTime' = $Event.TimeCreated
                        }
        $userinfo=New-Object -TypeName psobject -Property $properties
        Write-Output $userinfo
		}
    }
}

function Send-File {
##############################################################################
##
## Send-File
##
## From Windows PowerShell Cookbook (O'Reilly)
## by Lee Holmes (http://www.leeholmes.com/guide)
##
##############################################################################

<#

.SYNOPSIS

Sends a file to a remote session.

.EXAMPLE

PS >$session = New-PsSession leeholmes1c23
PS >Send-File c:\temp\test.exe c:\temp\test.exe $session

#>

param(
    ## The path on the local computer
    [Parameter(Mandatory = $true)]
    $Source,

    ## The target path on the remote computer
    [Parameter(Mandatory = $true)]
    $Destination,

    ## The session that represents the remote computer
    [Parameter(Mandatory = $true)]
    [System.Management.Automation.Runspaces.PSSession] $Session
)

Set-StrictMode -Version Latest

## Get the source file, and then get its content
$sourcePath = (Resolve-Path $source).Path
$sourceBytes = [IO.File]::ReadAllBytes($sourcePath)
$streamChunks = @()

## Now break it into chunks to stream
$streamSize = 1MB
for($position = 0; $position -lt $sourceBytes.Length;
    $position += $streamSize)
{
    $remaining = $sourceBytes.Length - $position
    $remaining = [Math]::Min($remaining, $streamSize)

    $nextChunk = New-Object byte[] $remaining
    [Array]::Copy($sourcebytes, $position, $nextChunk, 0, $remaining)
    $streamChunks += ,$nextChunk
}

$remoteScript = {
    param($destination, $length)

    ## Convert the destination path to a full file system path (to support
    ## relative paths)
    $Destination = $executionContext.SessionState.`
        Path.GetUnresolvedProviderPathFromPSPath("$env:temp\$Destination")

    ## Create a new array to hold the file content
    $destBytes = New-Object byte[] $length
    $position = 0

    ## Go through the input, and fill in the new array of file content
    foreach($chunk in $input)
    {
        [GC]::Collect()
        [Array]::Copy($chunk, 0, $destBytes, $position, $chunk.Length)
        $position += $chunk.Length
    }

    ## Write the content to the new file
    [IO.File]::WriteAllBytes($destination, $destBytes)

    [GC]::Collect()
}

## Stream the chunks into the remote script
$streamChunks | Invoke-Command -Session $session $remoteScript `
    -ArgumentList $destination,$sourceBytes.Length -ErrorAction Stop
}

function get-fileaudit{
    <#
    .Synopsis
       Get delete file event info from security log
    .DESCRIPTION
       reads in event ID 4663 for delete files over the last 24 hours
       REQUIRMENT:
        you need to be auditing file system
        https://technet.microsoft.com/en-us/library/dd408940%28v=WS.10%29.aspx?f=255&MSPPError=-2147217396#BKMK_step2
    .EXAMPLE
       get-logins
    .EXAMPLE
       get-logins
    #>
        $date = (get-date).AddHours(-24)
        $Events = Get-WinEvent -FilterHashtable @{Logname='Security';Id=4663;starttime=$date}
    
        foreach ($Event in $Events) {
            $EventXML = [XML]$Event.ToXML()
            $dateandtime = $Events[0].TimeCreated
            #$EventXML.Event.EventData.Data."#text"[9]
            switch ($EventXML.Event.EventData.Data."#text"[9]) {

                "0x1" { $action = "FILE_READ_DATA or FILE_LIST_DIRECTORY" }
                "0x2" { $action = "FILE_WRITE_DATA or FILE_ADD_FILE" }
                "0x4" { $action = "FILE_APPEND_DATA or FILE_ADD_SUBDIRECTORY" }
                "0x8" { $action = "FILE_READ_EA" }
                "0x10" { $action = "FILE_WRITE_EA" }
                "0x20" { $action = "FILE_EXECUTE or FILE_TRAVERSE" }
                "0x40" { $action = "FILE_DELETE_CHILD" }
                "0x80" { $action = "FILE_READ_ATTRIBUTES" }
                "0x100" { $action = "FILE_WRITE_ATTRIBUTES" }
                "0x10000" { $action = "DELETE" }
                "0x20000" { $action = "READ_CONTROL" }
                "0x40000" { $action = "WRITE_DAC" }
                "0x80000" { $action = "WRITE_OWNER" }
                "0x100000" { $action = "SYNCHRONIZE" }
                
                Default {$action = $EventXML.Event.EventData.Data."#text"[9]}
            }

            $properties = @{
                            'ProcessName' = $EventXML.Event.EventData.Data."#text"[11];
                            'ObjectName' = $EventXML.Event.EventData.Data."#text"[6];
                            'SubjectUserName' = $EventXML.Event.EventData.Data."#text"[1];
                            'SubjectDomainName' = $EventXML.Event.EventData.Data."#text"[2];
                            'ObjectType' = $EventXML.Event.EventData.Data."#text"[5];
                            'ResourceAttributes' = $EventXML.Event.EventData.Data."#text"[12];
                            'AccessMask' = $EventXML.Event.EventData.Data."#text"[9];
                            'Action' = $action
                            'DateandTime' = $dateandtime
                            }
            $userinfo=New-Object -TypeName psobject -Property $properties
            Write-Output $userinfo
        }
    }

#do not work to mount client shadow copys - only full os shadow copies
function Get-VolumeShadowCopy{
	<#
	.SYNOPSIS
		Get list of Volume Shadow Copies on the system
	
	.DESCRIPTION
		Get list of Volume Shadow Copies on the system
	
	.NOTES
		Additional information about the function.
	.EXAMPLE
		Get-VolumeShadowCopy
	.EXAMPLE
		$Vshadows = Get-VolumeShadowCopy
	#>
	
	[CmdletBinding()]
	[OutputType([System.Management.ManagementObject])]
	param ()
	
	Write-Verbose "testing if using elevated command prompt"
	$UserIdentity = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent())
	if (-not $UserIdentity.IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator'))
	{
		Throw 'You must run Get-VolumeShadowCopy from an elevated command prompt.'
	}
	
	Write-Verbose "getting VolumeShadowCopy data"
	$VShadows = Get-WmiObject Win32_ShadowCopy
	Write-Verbose "getting drive data"
	$allvolumes = Get-WmiObject win32_volume
	foreach ($shadow in $VShadows)
	{
		$properties = @{
			DeviceObject = $shadow.DeviceObject
			InstallDate = [datetime]::ParseExact($shadow.InstallDate.Split(".")[0], "yyyyMMddHHmmss", $null)
			VolumeName = $shadow.VolumeName
			OriginatingMachine = $shadow.OriginatingMachine
			DriveLetter = $($allvolumes | ? { $_.deviceid -eq $shadow.volumename } | select -ExpandProperty name)
		}
		Write-Verbose "creating custom VolumeShadowCopy object"
		$object = New-Object -TypeName psobject -Property $properties
		$object.pstypenames.insert(0, "System.Management.ManagementObject#root\cimv2\Win32_ShadowCopy.ADLantrx")
		Write-Output $object
	}
}

function New-VolumeShadowCopy{
	<#
	.SYNOPSIS
		Creates Volume Shadow Copy of the requested drive
	
	.DESCRIPTION
		Creates Volume Shadow Copy of the requested drive
	
	.PARAMETER DriveLetter
		Drive letter that you want to take a Volume Shadow Copy of
		ie: c:\
	
	.NOTES
		Additional information about the function.
	.EXAMPLE
		New-VolumeShadowCopy
	#>
	
	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory = $true)]
		[ValidatePattern('^\w:\\')]
		[string]$DriveLetter
	)
	
	Write-Verbose "testing if using elevated command prompt"
	$UserIdentity = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent())
	if (-not $UserIdentity.IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator'))
	{
		Throw 'You must run Get-VolumeShadowCopy from an elevated command prompt.'
	}
	
	# get static method
	$class = [WMICLASS]"root\cimv2:win32_shadowcopy"
	
	
	# create a new shadow copy
	Write-Verbose "Creating a new VoluemShadowCopy"
	#$class.create("C:\", "ClientAccessible")
	$return = $class.create("$DriveLetter", "ClientAccessible")
	Write-Verbose "Checking VolumeShadowCopy creation Status"
	switch ($return.returnvalue)
	{
		1 { Write-Error "Access denied."; break }
		2 { Write-Error "Invalid argument."; break }
		3 { Write-Error "Specified volume not found."; break }
		4 { Write-Error "Specified volume not supported."; break }
		5 { Write-Error "Unsupported shadow copy context."; break }
		6 { Write-Error "Insufficient storage."; break }
		7 { Write-Error "Volume is in use."; break }
		8 { Write-Error "Maximum number of shadow copies reached."; break }
		9 { Write-Error "Another shadow copy operation is already in progress."; break }
		10 { Write-Error "Shadow copy provider vetoed the operation."; break }
		11 { Write-Error "Shadow copy provider not registered."; break }
		12 { Write-Error "Shadow copy provider failure."; break }
		13 { Write-Error "Unknown error."; break }
		default { break }
	}
}

function Remove-VolumeShadowCopy{
	<#
	.SYNOPSIS
		Removes Volume Shadow Copy from system
	
	.DESCRIPTION
		Removes Volume Shadow Copy from system
	
	.PARAMETER DeviceObject
		DeviceObject of VolumeShadowCopy you want to remove
		ie: "\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy22"
	
	.NOTES
		Additional information about the function.
	.EXAMPLE
		Remote-VolumeShadowCopy
	#>
	
	[CmdletBinding(ConfirmImpact = 'High',
				   SupportsShouldProcess = $true)]
	param
	(
		[Parameter(Mandatory = $true,
				   ValueFromPipeline = $true)]
		[ValidatePattern('^\\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy[0-9]{1,3}$')]
		[string]$DeviceObject
	)
	
	Write-Verbose "testing if using elevated command prompt"
	$UserIdentity = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent())
	if (-not $UserIdentity.IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator'))
	{
		Throw 'You must run Get-VolumeShadowCopy from an elevated command prompt.'
	}
	
	if ($PSCmdlet.ShouldProcess("The VolumeShadowCopy at DevicePath $DevicePath will be removed"))
	{
		Write-Verbose "retreving and removing VolumeShadowCopy"
		(Get-WmiObject -Namespace root\cimv2 -Class Win32_ShadowCopy | Where-Object { $_.DeviceObject -eq $DeviceObject }).Delete()
	}
}

function Mount-VolumeShadowCopy{
	<#
	.SYNOPSIS
		Mounts Volume Shadow Copy
	
	.DESCRIPTION
		Mounts Volume Shadow Copy
		Will mount the Volume Shadow Copy with in the folder specified with the drive letter
		  date of when the Volume Shadow Copy was orignially taken
	
	.PARAMETER Path
		Path to directory that will hold the mounted Volume Shadow Copy
	
	.PARAMETER DeviceObject
		Volume Shadow Copy DeviceObject that you want mounted
		ie: "\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy22"
	
	.NOTES
		Additional information about the function.
	.EXAMPLE
		Mount-VolumeShadowCopy -path c:\temp -DeviceObject "\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy22"
		    	Directory: C:\temp
			Mode                LastWriteTime     Length Name
			----                -------------     ------ ----
			d----          8/1/2017  12:52 PM            Drive_C_20170724
	#>
	
	param
	(
		[Parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[String]$Path,
		[Parameter(Mandatory = $true)]
		[ValidatePattern('^\\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy[0-9]{1,3}$')]
		[String[]]$DeviceObject
	)
	
	$UserIdentity = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent())
	
	if (-not $UserIdentity.IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator'))
	{
		Throw 'You must run Get-VolumeShadowCopy from an elevated command prompt.'
	}
	
	# Validate that the path exists before proceeding
	Get-ChildItem $Path -ErrorAction Stop | Out-Null
	
	$DynAssembly = New-Object System.Reflection.AssemblyName('VSSUtil')
	$AssemblyBuilder = [AppDomain]::CurrentDomain.DefineDynamicAssembly($DynAssembly, [Reflection.Emit.AssemblyBuilderAccess]::Run)
	$ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('VSSUtil', $False)
	
	# Define [VSS.Kernel32]::CreateSymbolicLink method using reflection
	# (i.e. none of the forensic artifacts left with using Add-Type)
	$TypeBuilder = $ModuleBuilder.DefineType('VSS.Kernel32', 'Public, Class')
	$PInvokeMethod = $TypeBuilder.DefinePInvokeMethod('CreateSymbolicLink',
		'kernel32.dll',
		([Reflection.MethodAttributes]::Public -bor [Reflection.MethodAttributes]::Static),
		[Reflection.CallingConventions]::Standard,
		[Bool],
		[Type[]]@([String], [String], [UInt32]),
		[Runtime.InteropServices.CallingConvention]::Winapi,
		[Runtime.InteropServices.CharSet]::Auto)
	$DllImportConstructor = [Runtime.InteropServices.DllImportAttribute].GetConstructor(@([String]))
	$SetLastError = [Runtime.InteropServices.DllImportAttribute].GetField('SetLastError')
	$SetLastErrorCustomAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($DllImportConstructor,
		@('kernel32.dll'),
		[Reflection.FieldInfo[]]@($SetLastError),
		@($true))
	$PInvokeMethod.SetCustomAttribute($SetLastErrorCustomAttribute)
	
	$Kernel32Type = $TypeBuilder.CreateType()
	
	$shadows = Get-VolumeShadowCopy | ? { $_.deviceobject -eq $DeviceObject }
	$date = get-date $shadows.InstallDate -Format yyyyMMdd
	$folder = "Drive_$($shadows.DriveLetter[0])_$date"
	
	$LinkPath = Join-Path $Path $folder
	
	if (Test-Path $LinkPath)
	{
		Write-Warning "'$LinkPath' already exists."
		continue
	}
	
	if (-not $Kernel32Type::CreateSymbolicLink($LinkPath, "$($DeviceObject)\", 1))
	{
		Write-Error "Symbolic link creation failed for '$DeviceObject'."
		continue
	}
	
	#Get-Item $LinkPath
}

function Dismount-VolumeShadowCopy{
	
	<#
	.SYNOPSIS
		Removes mounted Volume Shadow Copy
	
	.DESCRIPTION
		Removes mounted Volume Shadow Copy
	
	.PARAMETER Path
		Path to Volume Shadow Copy mount point Directory
	
	.NOTES
		Additional information about the function.
	.EXAMPLE
		Dismount-VolumeShadowCopy -path c:\temp\Drive_C_20170724
	
	#>
	
	[CmdletBinding(ConfirmImpact = 'High',
				   SupportsShouldProcess = $true)]
	param
	(
		[Parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[String]$Path
	)
	
	Write-Verbose "testing if using elevated command prompt"
	$UserIdentity = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent())
	if (-not $UserIdentity.IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator'))
	{
		Throw 'You must run Get-VolumeShadowCopy from an elevated command prompt.'
	}
	
	#TODO: Place script here
	if ($PSCmdlet.ShouldProcess("The Mounted VolumeShadowCopy at path $Path will be removed"))
	{
		Write-Verbose "getting Directory and removing junction point $path"
		(Get-Item -Path $Path).delete()
	}
	
}

Function Get-RebootHistory {  
    <# 
        .SYNOPSIS 
            Retrieves historical information about shutdown/restart events from one or more remote computers. 
     
        .DESCRIPTION 
            The Get-RebootHistory function uses Windows Management Instrumentation (WMI) to retrieve information about all shutdown events from a remote computer.   
             
            Using this function, you can analyze shutdown events across a large number of computers to determine how frequently shutdown/restarts are occurring, whether unexpected shutdowns are occurring and quickly identify the source of the last clean shutdown/restart. 
             
            Data returned includes date/time information for all available boot history events (e.g. restarts, shutdowns, unexpected shutdowns, etc.), date/time information for unexpected reboots and detailed information about the last clean shutdown including date/time, type, initiating user, initiating process and reason.      
             
            Because Get-RebootHistory uses WMI to obtain shutdown event history from the system event log, it is fully supported against both legacy and current versions of Windows including legacy versions that do not support filtering of event logs through standard methods.  
         
        .PARAMETER ComputerName 
            Accepts a single computer name or an array of computer names separated by commas (e.g. "prod-web01","prod-web02").  
 
            This is an optional parameter, the default value is the local computer ($Env:ComputerName). 
         
        .PARAMETER Credential 
            Accepts a standard credential object. 
             
            This is an optional parameter and is only necessary when the running user does not have access to the remote computer(s). 
 
        .EXAMPLE 
            .\Get-RebootHistory -ComputerName prod-web01,prod-web02 -Credential (Get-Credential) 
         
            Get boot history for multiple remote computers with alternate credentials.  
         
        .EXAMPLE 
            .\Get-RebootHistory -ComputerName prod-web01,prod-web02 -Credential (Get-Credential) | ? { $_.PercentDirty -ge 30 } 
         
            Get a list of computers experiencing a high percentage of unexpected shutdown events. 
         
        .EXAMPLE  
            .\Get-RebootHistory -ComputerName prod-web01,prod-web02 -Credential (Get-Credential) | ? { $_.RecentShutdowns -ge 3 }  
         
            Return information about servers that have been experiencing frequent shutdown/reboot events over the last 30 days. 
         
        .OUTPUTS 
            System.Management.Automation.PSCustomObject  
             
            Return object includes the following properties:  
             
                Computer                 
                BootHistory                : Array of System.DateTime objects for all recorded instances of the system booting (clean or otherwise). 
                RecentShutdowns            : The number of shutdown/restart events in the last 30 days. 
                UnexpectedShutdowns        : Array of System.DateTime objects for all recorded unexpected shutdown events. 
                RecentUnexpected        : The number of unexpected shutdown events in the last 30 days. 
                PercentDirty            : The percentage of shutdown events that were unexpected (UnexpectedShutdowns/BootHistory). 
                LastShutdown            : System.DateTime object of the last clean shutdown event. 
                LastShutdownType        : Type of the last clean shutdown event (Restart | Shutdown). 
                LastShutdownUser        : The user who initiated the last clean shutdown event. 
                LastShutdownProcess        : The process that initiated the last clean shutdown event. 
                LastShutdownReason        : If available, the reason code and comments for the last clean shutdown event. 
                 
        .NOTES 
            Author            : Eric Westfall 
            Email            : eawestfall@gmail.com 
            Script Version    : 1.1 
            Revision Date    : 11/26/2014
			https://gallery.technet.microsoft.com/scriptcenter/Get-RebootHistory-bc804819
    #> 
     
    Param ( 
        [Parameter(Mandatory = $False, Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)] 
        [Alias("CN","Computer")] 
        [Array]$ComputerName = $Env:ComputerName, 
 
        [Parameter(Mandatory = $False, Position = 1, ValueFromPipeline = $False)] 
        [Alias("Cred")] 
        [ValidateNotNull()] 
        [System.Management.Automation.PSCredential]$Credential = [System.Management.Automation.PSCredential]::Empty 
    ) 
     
    Begin { 
        $i = 0 
        $RecentShutdowns = 0 
        $RecentUnexpected = 0 
         
        $BootHistory = @() 
        $ShutdownDetail = @() 
        $UnexpectedShutdowns = @()  
         
        # Store original credential, if we attempt to make a local connection we need to  
        # temporarily empty out the credential object. 
        $Original_Credential = $Credential 
         
        # Select properties defined to ensure proper display order. 
        $BootInformation = @( 
            "Computer" 
            "BootHistory" 
            "RecentShutdowns" 
            "UnexpectedShutdowns" 
            "RecentUnexpected" 
            "PercentDirty" 
            "LastShutdown" 
            "LastShutdownType" 
            "LastShutdownUser" 
            "LastShutdownProcess" 
            "LastShutdownReason" 
        ) 
         
        # Arguments to be passed to our WMI call.  
        $Params = @{ 
            ErrorAction        = 'Stop' 
            ComputerName    = $Computer 
            Credential        = $Credential 
            Class            = 'Win32_NTLogEvent' 
            Filter            = "LogFile = 'System' and EventCode = 6009 or EventCode = 6008 or EventCode = 1074" 
        } 
    } 
 
    Process { 
        ForEach ($Computer In $ComputerName) { 
            $Params.ComputerName = $Computer 
             
            # You can't use credentials when connecting to the local machine so temporarily empty out the credential object. 
            If ($Computer -eq $Env:ComputerName) {  
                $Params.Credential = [System.Management.Automation.PSCredential]::Empty 
            } 
             
            If ($ComputerName.Count -gt 1) {  
                Write-Progress -Id 1 -Activity "Retrieving boot history." -Status ("Percent Complete: {0:N0}" -f $($i / $($ComputerName.Count)*100)) -PercentComplete (($i / $ComputerName.Count)*100); $i++ 
            } Else {  
                Write-Progress -Id 1 -Activity "Retrieving boot history." 
            } 
 
            Try {  
                $d = 0 
                $Events = Get-WmiObject @Params 
                 
                ForEach ($Event In $Events) {  
                    Write-Progress -Id 2 -ParentId 1 -Activity "Processing reboot history." -PercentComplete (($d / $Events.Count)*100); $d++ 
                     
                    # Record the relevant details for the shutdown event. 
                    Switch ($Event.EventCode) {  
                        6009 { $BootHistory += (Get-Date(([WMI]'').ConvertToDateTime($Event.TimeGenerated)) -Format g) } 
                        6008 { $UnexpectedShutdowns += ('{0} {1}' -f ($Event.InsertionStrings[1], $Event.InsertionStrings[0])) } 
                        1074 { $ShutdownDetail += $Event } 
                    } 
                } 
                 
                # We explicitly ignore exceptions originating from this process since some versions of Windows may store dates in invalid formats (e.g. ?11/?16/?2014) in the event log after an unexpected shutdown causing this calculation to fail. 
                Try {  
                    $RecentUnexpected = ($UnexpectedShutdowns | ? { ((Get-Date)-(Get-Date $_)).TotalDays -le 30 }).Count 
                } Catch {  
                    $RecentUnexpected = "Unable to calculate." 
                }  
                 
                # Grab details about the last clean shutdown and generate our return object. 
                $ShutdownDetail | Select -First 1 | ForEach-Object {  
                    New-Object -TypeName PSObject -Property @{ 
                        Computer = $Computer 
                        BootHistory = $BootHistory  
                        RecentUnexpected = $RecentUnexpected 
                        LastShutdownUser = $_.InsertionStrings[6] 
                        UnexpectedShutdowns = $UnexpectedShutdowns 
                        LastShutdownProcess = $_.InsertionStrings[0] 
                        PercentDirty = '{0:P0}' -f (($UnexpectedShutdowns.Count/$BootHistory.Count)) 
                        LastShutdownType = (Get-Culture).TextInfo.ToTitleCase($_.InsertionStrings[4]) 
                        LastShutdown = (Get-Date(([WMI]'').ConvertToDateTime($_.TimeGenerated)) -Format g) 
                        RecentShutdowns = ($BootHistory | ? { ((Get-Date)-(Get-Date $_)).TotalDays -le 30 }).Count 
                        LastShutdownReason = 'Reason Code: {0}, Reason: {1}' -f ($_.InsertionStrings[3], $_.InsertionStrings[2]) 
                    } | Select $BootInformation     
                }             
            } Catch [System.Exception] {  
                # We explicitly ignore exceptions originating from Get-Date since some versions of Windows may store dates in invalid formats in the event log after an unexpected shutdown. 
                If ($_.CategoryInfo.Activity -ne 'Get-Date') {  
                    Write-Warning ("Unable to retrieve boot history for {0}. `nError Details: {1}" -f ($Computer, $_)) 
                } 
            } 
             
            # Reset credential object since we may have temporarily overwrote it to deal with local connections. 
            $Params.Credential = $Original_Credential 
        } 
    } 
} 
 
function Get-uptime{
<#
	.SYNOPSIS
		get's the last time the system was rebooted
	
	.DESCRIPTION
		A detailed description of the Get-uptime function.
	
	.PARAMETER computername
		pc name if nothing it provided it defaults to local host
	
	.EXAMPLE
				PS C:\> Get-uptime -computername 'Value1'
	
	.NOTES
		Additional information about the function.
#>
	
	[CmdletBinding()]
	param
	(
		[Parameter(Position = 0)]
		[string]$computername = "."
	)
	
	Get-WmiObject win32_operatingsystem -computername $computername | select csname, @{ LABEL = 'LastBootUpTime'; EXPRESSION = { $_.ConverttoDateTime($_.lastbootuptime) } }
	
}


write-output "!!!! Finished installing scripts from Lantrx !!!!"
