[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string]$MsiPath
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$resolvedMsi = (Resolve-Path -LiteralPath $MsiPath).Path
$installer = New-Object -ComObject WindowsInstaller.Installer
$invoke = [Reflection.BindingFlags]::InvokeMethod
$get = [Reflection.BindingFlags]::GetProperty
$database = $installer.GetType().InvokeMember(
    "OpenDatabase",
    $invoke,
    $null,
    $installer,
    @($resolvedMsi, 0))

function Get-MsiScalar {
    param(
        [Parameter(Mandatory = $true)][string]$Query,
        [switch]$Integer
    )

    $view = $database.GetType().InvokeMember(
        "OpenView", $invoke, $null, $database, @($Query))
    $view.GetType().InvokeMember(
        "Execute", $invoke, $null, $view, $null) | Out-Null
    $record = $view.GetType().InvokeMember(
        "Fetch", $invoke, $null, $view, $null)
    if ($null -eq $record) {
        return $null
    }

    $property = if ($Integer) { "IntegerData" } else { "StringData" }
    return $record.GetType().InvokeMember(
        $property, $get, $null, $record, @(1))
}

function Get-MsiProperty {
    param([Parameter(Mandatory = $true)][string]$Name)
    Get-MsiScalar -Query (
        "SELECT ``Value`` FROM ``Property`` WHERE ``Property`` = '$Name'")
}

function Get-MsiSequence {
    param([Parameter(Mandatory = $true)][string]$Action)
    Get-MsiScalar -Integer -Query (
        "SELECT ``Sequence`` FROM ``InstallExecuteSequence`` " +
        "WHERE ``Action`` = '$Action'")
}

function Assert-Equal {
    param($Actual, $Expected, [string]$Message)
    if ($Actual -ne $Expected) {
        throw "$Message Expected '$Expected', received '$Actual'."
    }
}

Assert-Equal (Get-MsiProperty "ProductName") "FindGT" "ProductName mismatch."
Assert-Equal (Get-MsiProperty "Manufacturer") "Родченко Александр" "Manufacturer mismatch."
$summary = $database.GetType().InvokeMember(
    "SummaryInformation", $get, $null, $database, @(0))
$template = $summary.GetType().InvokeMember(
    "Property", $get, $null, $summary, @(7))
Assert-Equal $template "x64;1049" "MSI template mismatch."
Assert-Equal (Get-MsiSequence "RemoveExistingProducts") 1501 "Major-upgrade schedule mismatch."
Assert-Equal (
    Get-MsiScalar -Query (
        "SELECT ``StartName`` FROM ``ServiceInstall`` WHERE ``Name`` = 'FindGT'")
) "LocalSystem" "Service account mismatch."
Assert-Equal (
    Get-MsiScalar -Integer -Query (
        "SELECT ``StartType`` FROM ``ServiceInstall`` WHERE ``Name`` = 'FindGT'")
) 2 "Service start type mismatch."

$orderedActions = @(
    "CreateFolders",
    "SecureProgramData",
    "InstallFiles",
    "InstallAuthzSource",
    "InstallServices",
    "ConfigureServiceRecovery",
    "StartServices"
)
$sequences = @{}
foreach ($action in $orderedActions) {
    $sequences[$action] = Get-MsiSequence $action
}
for ($index = 1; $index -lt $orderedActions.Count; $index++) {
    $previous = $orderedActions[$index - 1]
    $current = $orderedActions[$index]
    if ($sequences[$previous] -ge $sequences[$current]) {
        throw "MSI action ordering is invalid: $previous must precede $current."
    }
}

$secureProperties = Get-MsiProperty "SecureCustomProperties"
foreach ($property in @(
    "START_SERVICE",
    "ANALYZE_EXISTING_SESSIONS",
    "ENABLE_OPERATIONAL_SINK",
    "SECURITY_SINK_MODE",
    "ENABLE_JSON_SINK",
    "POWERFUL_ONLY",
    "PRESERVE_CONFIG_ON_UNINSTALL",
    "PRESERVE_STATE_ON_UNINSTALL"
)) {
    if ($secureProperties -notmatch "(^|;)$property(;|$)") {
        throw "SecureCustomProperties is missing $property."
    }
}

$fileView = $database.GetType().InvokeMember(
    "OpenView", $invoke, $null, $database, @("SELECT ``FileName`` FROM ``File``"))
$fileView.GetType().InvokeMember(
    "Execute", $invoke, $null, $fileView, $null) | Out-Null
$files = @()
while ($true) {
    $record = $fileView.GetType().InvokeMember(
        "Fetch", $invoke, $null, $fileView, $null)
    if ($null -eq $record) {
        break
    }
    $files += $record.GetType().InvokeMember(
        "StringData", $get, $null, $record, @(1))
}
$longFileNames = [Collections.Generic.HashSet[string]]::new(
    [StringComparer]::OrdinalIgnoreCase)
foreach ($file in $files) {
    [void]$longFileNames.Add(($file -split "\|")[-1])
}

if ($longFileNames.Where({
    $_ -match "WinSample|LsaSecretExtractor|\.pdb$"
}).Count -ne 0) {
    throw "MSI contains excluded research or debug payload."
}
foreach ($required in @(
    "FindGT.exe",
    "FindGT.Service.exe",
    "FindGT.Core.dll",
    "FindGT.Eventing.dll",
    "FindGT.EventMessages.dll",
    "FindGT.SecurityMessages.dll",
    "FindGT.man",
    "FindGT.settings.json"
)) {
    if (-not $longFileNames.Contains($required)) {
        throw "MSI payload is missing $required."
    }
}

[PSCustomObject]@{
    Path = $resolvedMsi
    ProductVersion = Get-MsiProperty "ProductVersion"
    ProductCode = Get-MsiProperty "ProductCode"
    SHA256 = (Get-FileHash -LiteralPath $resolvedMsi -Algorithm SHA256).Hash
    FileCount = $files.Count
}
