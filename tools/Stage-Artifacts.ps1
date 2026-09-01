[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern("^\d+\.\d+\.\d+$")]
    [string]$ProductVersion,
    [string]$Configuration = "Release",
    [string]$OutputDirectory = "artifacts"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$root = Split-Path -Parent $PSScriptRoot
$output = [IO.Path]::GetFullPath((Join-Path $root $OutputDirectory))
if (Test-Path -LiteralPath $output) {
    Remove-Item -LiteralPath $output -Recurse -Force
}
New-Item -ItemType Directory -Path $output | Out-Null

$msi = Join-Path $root (
    "FindGT.Setup\bin\x64\$Configuration\FindGT-$ProductVersion-x64.msi")
Copy-Item -LiteralPath $msi -Destination $output

$portable = Join-Path $output "portable"
New-Item -ItemType Directory -Path $portable | Out-Null
foreach ($path in @(
    "FindGT\bin\x64\$Configuration\FindGT.exe",
    "FindGT\bin\x64\$Configuration\FindGT.exe.config",
    "FindGT\bin\x64\$Configuration\Spectre.Console.dll",
    "FindGT\bin\x64\$Configuration\Spectre.Console.Cli.dll",
    "FindGT\bin\x64\$Configuration\System.Buffers.dll",
    "FindGT\bin\x64\$Configuration\System.IO.FileSystem.AccessControl.dll",
    "FindGT\bin\x64\$Configuration\System.Memory.dll",
    "FindGT\bin\x64\$Configuration\System.Numerics.Vectors.dll",
    "FindGT\bin\x64\$Configuration\System.Runtime.CompilerServices.Unsafe.dll",
    "FindGT\bin\x64\$Configuration\System.Security.AccessControl.dll",
    "FindGT\bin\x64\$Configuration\System.Security.Permissions.dll",
    "FindGT\bin\x64\$Configuration\System.Security.Principal.Windows.dll",
    "FindGT.Service\bin\x64\$Configuration\FindGT.Service.exe",
    "FindGT.Service\bin\x64\$Configuration\FindGT.Service.exe.config",
    "FindGT.Service\bin\x64\$Configuration\FindGT.Core.dll",
    "FindGT.Service\bin\x64\$Configuration\FindGT.Eventing.dll",
    "FindGT.Service\bin\x64\$Configuration\FindGT.settings.json",
    "FindGT.EventMessages\bin\x64\$Configuration\FindGT.EventMessages.dll",
    "FindGT.EventMessages\bin\x64\$Configuration\FindGT.SecurityMessages.dll",
    "FindGT.EventMessages\bin\x64\$Configuration\FindGT.man",
    "LICENSE.txt",
    "README.md",
    "README.ru.md",
    "README.el.md"
)) {
    Copy-Item -LiteralPath (Join-Path $root $path) -Destination $portable
}
Compress-Archive -Path (Join-Path $portable "*") `
    -DestinationPath (Join-Path $output "FindGT-$ProductVersion-portable.zip")
Remove-Item -LiteralPath $portable -Recurse -Force

$symbols = Join-Path $output "symbols"
New-Item -ItemType Directory -Path $symbols | Out-Null
foreach ($path in @(
    "FindGT\bin\x64\$Configuration\FindGT.pdb",
    "FindGT.Core\bin\x64\$Configuration\FindGT.Core.pdb",
    "FindGT.Eventing\bin\x64\$Configuration\FindGT.Eventing.pdb",
    "FindGT.Service\bin\x64\$Configuration\FindGT.Service.pdb",
    "FindGT.Setup\bin\x64\$Configuration\FindGT-$ProductVersion-x64.wixpdb"
)) {
    Copy-Item -LiteralPath (Join-Path $root $path) -Destination $symbols
}
Compress-Archive -Path (Join-Path $symbols "*") `
    -DestinationPath (Join-Path $output "FindGT-$ProductVersion-symbols.zip")
Remove-Item -LiteralPath $symbols -Recurse -Force

Get-ChildItem -LiteralPath $output -File |
    Select-Object Name, Length, FullName
