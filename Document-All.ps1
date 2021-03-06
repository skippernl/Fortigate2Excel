<#
.SYNOPSIS
Fortigate2Excel parses the configuration from a FortiGate device into a Excel file.
.DESCRIPTION
The Fortigate2Excel reads a FortiGate config file and pulls out the configuration for each VDOM in the file into excel.
.PARAMETER SrcDir
[REQUIRED] This is the path to the FortiGate config/credential files
Optional switches are explained in the Fortigate2Excel script  
.NOTES
Author: Xander Angenent (@XaAng70)
Idea: Drew Hjelm (@drewhjelm) (creates csv of ruleset only)
Last Modified: 2020/11/05
#>
Param
(
    [Parameter(Mandatory = $true)]
    $SrcDir,
    [switch]$SkipFilter = $false,
    [switch]$SkipFortiISDB = $false,
    [switch]$SkipTimeZone = $false
)

Function CreateFiles ($ConfigFilesArray) {
    Foreach ( $ConfigFile in $ConfigFilesArray ) {
        $PSArgument = $BaseArgumentList
        $PSArgument += "-FortigateConfig '$($ConfigFile.FullName)'"
        Invoke-Expression ".\Fortigate2Excel.ps1 $PSArgument"
    }
}

$BaseArgumentList = @()
$PSArgument = @()
if ($SkipFilter) { $BaseArgumentList += "-Skipfilter" }
if ($SkipFortiISDB) { $BaseArgumentList += "-SkipFortiISDB" }
if ($SkipTimeZone) { $BaseArgumentList += "-SkipTimeZone" }

#Get All *.conf Files
if (!(Test-Path $SrcDir)) {
    Write-Output "Path not found stopping script."
    exit 1
}
$GetConfigFiles = $SrcDir + "\" + "*.conf"
$ConfigFiles = Get-ChildItem $GetConfigFiles | Sort-Object Name
If ($ConfigFiles) { CreateFiles $ConfigFiles }
else { 
    Write-Output "No config (*.conf) files found."
}
$GetConfigFiles = $SrcDir + "\" + "*.cred"
$ConfigFiles = Get-ChildItem $GetConfigFiles | Sort-Object Name
If ($ConfigFiles) { CreateFiles $ConfigFiles }
else {
    Write-Output "No credential (*.cred) files found."
}
