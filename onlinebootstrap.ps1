#installed powershell scripts link into powershell 
function install-onlinescripts{
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
        [parameter(ParameterSetName='Server')][switch]$server,
        # Exchange online scripts
        [parameter(ParameterSetName='Exchange')][switch]$Exchange
        #windows 7 desktop online scripts
        #[parameter(ParameterSetName='Windows 7')][switch]$windows7
    )
        
    Begin
    {
        $filelocaiton = "https://raw.githubusercontent.com/pcwork57/System-prep/rebrand/"
    }#end begin
    Process
    {

        switch ($PSCmdlet.ParameterSetName) {
            "Desktop" {Write-Verbose "desktop online script chosen"
            $file = "onlinedesktop.ps1"}
            "Hyper-V" {Write-Verbose "hyperv online script chosen"
            $file = "onlinehyperv.ps1"}
            "Server"{write-verbose "server online script chosen"
            $file = "onlineserver.ps1"}
            "Exchange"{write-verbose "Winodws 10 online script chosen"
            $file = "onlineexchange.ps1"}
            #"Windows 7"{write-verbose "Windows 7 online script chosen"
            #$file = "lantrxwindows7.ps1"}
            Default {}
        }
        $insert = "try{iex (New-Object System.Net.WebClient).DownloadString(`"$filelocaiton$file`")}catch{`"Error Loading Online Scripts`"} "        
        try{
            if(!(test-path $PROFILE.AllUsersAllHosts)){
                #New-Item -Path $PROFILE.AllUsersAllHosts -Type file -force -Value "iex (New-Object System.Net.WebClient).DownloadString(`"$filelocaiton$file`")" -ErrorAction Stop > $null
                New-Item -Path $PROFILE.AllUsersAllHosts -Type file -force -Value $insert -ErrorAction Stop > $null
            }else{
                if(!( gc $PROFILE.AllUsersAllHosts | Select-String $file )){
                    #Add-Content -Path $PROFILE.AllUsersAllHosts -Value "`r`niex (New-Object System.Net.WebClient).DownloadString(`"$filelocaiton$file`")" -ErrorAction Stop
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
function remove-onlinescripts {
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
        [parameter(ParameterSetName='Server')][switch]$server,
        #Exchange online scripts
        [parameter(ParameterSetName='Exchange')][switch]$Exchange
        #windows 7 desktop online scripts
        #[parameter(ParameterSetName='Windows 7')][switch]$windows7
    )
    
    begin {
        $filelocaiton = "https://raw.githubusercontent.com/pcwork57/System-prep/rebrand/"
    }#end begin
    process {
        switch ($PSCmdlet.ParameterSetName) {
            "Desktop" {Write-Verbose "desktop online script chosen"
            $file = "onlinedesktop.ps1"}
            "Hyper-V" {Write-Verbose "hyperv online script chosen"
            $file = "onlinehyperv.ps1"}
            "Server"{write-verbose "server online script chosen"
            $file = "onlineserver.ps1"}
            "Exchnage"{write-verbose "Exchange online script chosen"
            $file = "onlineexchange.ps1"}
            #"Windows 7"{write-verbose "Windows 7 online script chosen"
            #$file = "lantrxwindows7.ps1"}
            Default {}
        }
        $insert = "try{iex (New-Object System.Net.WebClient).DownloadString(`"$filelocaiton$file`")}catch{`"Error Loading Online Scripts`"} "

        try {
            $profilecontents = gc $PROFILE.AllUsersAllHosts -ErrorAction stop | Where-Object {$_ -notmatch $file}
            if ($profilecontents) {
                #New-Item -Path $PROFILE.AllUsersAllHosts -Type file -force -Value ($profilecontents.ToString()) -ErrorAction Stop #> $null
                (gc $PROFILE.AllUsersAllHosts) -notmatch $file | Out-File $PROFILE.AllUsersAllHosts
            }else {
                Remove-Item -Path $profile.AllUsersAllHosts -Force -ErrorAction Stop 
            }
            

        }
        catch{Write-error "Could NOT remote chosen lantrx scripts to pc profile"}
        
    }#end process
    end {
    }#end end
}
