#installed powershell scripts link into powershell 
function install-lantrxonlinescripts{
    <#
    .Synopsis
        Short description
    .DESCRIPTION
        Long description
    .EXAMPLE
        Example of how to use this cmdlet
    .EXAMPLE
        Another example of how to use this cmdlet
    #>
        
    [CmdletBinding(defaultparametersetname='desktop')]
    [OutputType([int])]
    Param
    (
        # Standard desktop online script
        [parameter(ParameterSetName='Desktop')][switch]$desktop,
        # Hyper-V online scripts
        [parameter(ParameterSetName='Hyper-V')][switch]$hyperv,
        # Windows server online scrips
        [parameter(ParameterSetName='Server')][switch]$server
        #windows 10 desktop online scripts
        #[parameter(ParameterSetName='Winodws 10')][switch]$windows10,
        #windows 7 desktop online scripts
        #[parameter(ParameterSetName='Windows 7')][switch]$windows7
    )
        
    Begin
    {
        $lantrxfilelocaiton = "https://rebrand.ly/"
    }#end begin
    Process
    {

        switch ($PSCmdlet.ParameterSetName) {
            "Desktop" {Write-Verbose "desktop online script chosen"
            $lantrxfile = "b1803"}
            "Hyper-V" {Write-Verbose "hyperv online script chosen"
            $lantrxfile = "b6f0c"}
            "Server"{write-verbose "server online script chosen"
            $lantrxfile = "bd6c0"}
            #"Winodws 10"{write-verbose "Winodws 10 online script chosen"
            #$lantrxfile = "lantrxwindows10.ps1"}
            #"Windows 7"{write-verbose "Windows 7 online script chosen"
            #$lantrxfile = "lantrxwindows7.ps1"}
            Default {}
        }
        $insert = "try{iex (New-Object System.Net.WebClient).DownloadString(`"$lantrxfilelocaiton$lantrxfile`")}catch{`"Error Loading Lantrx Scripts`"} "        
        try{
            if(!(test-path $PROFILE.AllUsersAllHosts)){
                #New-Item -Path $PROFILE.AllUsersAllHosts -Type file -force -Value "iex (New-Object System.Net.WebClient).DownloadString(`"$lantrxfilelocaiton$lantrxfile`")" -ErrorAction Stop > $null
                New-Item -Path $PROFILE.AllUsersAllHosts -Type file -force -Value $insert -ErrorAction Stop > $null
            }else{
                if(!( gc $PROFILE.AllUsersAllHosts | Select-String $lantrxfile )){
                    #Add-Content -Path $PROFILE.AllUsersAllHosts -Value "`r`niex (New-Object System.Net.WebClient).DownloadString(`"$lantrxfilelocaiton$lantrxfile`")" -ErrorAction Stop
                    Add-Content -Path $PROFILE.AllUsersAllHosts -Value "`r`n$insert" -ErrorAction Stop
                }else{
                    #nothing done if info exists in file
                }#end check file
            }#end test file
                        
        }Catch{Write-error "Could NOT install chosen lantrx scripts to pc profile"}

    }#end process
    End
    {
    }#end end
}#end function

#remove powershell scripts link from powershell
function remove-lantrxonlinescripts {
        <#
    .SYNOPSIS
        Short description
    .DESCRIPTION
        Long description
    .EXAMPLE
        Example of how to use this cmdlet
    .EXAMPLE
        Another example of how to use this cmdlet
    #>
    [CmdletBinding()]
    [OutputType([int])]
    param(
        # Standard desktop online script
        [parameter(ParameterSetName='Desktop')][switch]$desktop,
        # Hyper-V online scripts
        [parameter(ParameterSetName='Hyper-V')][switch]$hyperv,
        # Windows server online scrips
        [parameter(ParameterSetName='Server')][switch]$server
        #windows 10 desktop online scripts
        #[parameter(ParameterSetName='Winodws 10')][switch]$windows10,
        #windows 7 desktop online scripts
        #[parameter(ParameterSetName='Windows 7')][switch]$windows7
    )
    
    begin {
        $lantrxfilelocaiton = "https://rebrand.ly/"
    }#end begin
    process {
        switch ($PSCmdlet.ParameterSetName) {
            "Desktop" {Write-Verbose "desktop online script chosen"
            $lantrxfile = "b1803"}
            "Hyper-V" {Write-Verbose "hyperv online script chosen"
            $lantrxfile = "b6f0c"}
            "Server"{write-verbose "server online script chosen"
            $lantrxfile = "bd6c0"}
            #"Winodws 10"{write-verbose "Winodws 10 online script chosen"
            #$lantrxfile = "lantrxwindows10.ps1"}
            #"Windows 7"{write-verbose "Windows 7 online script chosen"
            #$lantrxfile = "lantrxwindows7.ps1"}
            Default {}
        }
        $insert = "try{iex (New-Object System.Net.WebClient).DownloadString(`"$lantrxfilelocaiton$lantrxfile`")}catch{`"Error Loading Lantrx Scripts`"} "

        try {
            $profilecontents = gc $PROFILE.AllUsersAllHosts -ErrorAction stop | Where-Object {$_ -notmatch $lantrxfile}
            if ($profilecontents) {
                #New-Item -Path $PROFILE.AllUsersAllHosts -Type file -force -Value ($profilecontents.ToString()) -ErrorAction Stop #> $null
                (gc $PROFILE.AllUsersAllHosts) -notmatch $lantrxfile | Out-File $PROFILE.AllUsersAllHosts
            }else {
                Remove-Item -Path $profile.AllUsersAllHosts -Force -ErrorAction Stop 
            }
            

        }
        catch{Write-error "Could NOT remote chosen lantrx scripts to pc profile"}
        
    }#end process
    end {
    }#end end
}
