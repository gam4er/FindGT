[CmdletBinding()]
param(
    [string]$Directory = "artifacts"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$root = Split-Path -Parent $PSScriptRoot
$resolved = [IO.Path]::GetFullPath((Join-Path $root $Directory))
if (-not (Test-Path -LiteralPath $resolved -PathType Container)) {
    throw "Artifact directory does not exist: $resolved"
}

$checksums = Get-ChildItem -LiteralPath $resolved -File |
    Where-Object Name -ne "SHA256SUMS.txt" |
    Sort-Object Name |
    ForEach-Object {
        $hash = Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256
        "{0} *{1}" -f $hash.Hash.ToLowerInvariant(), $_.Name
    }
$path = Join-Path $resolved "SHA256SUMS.txt"
[IO.File]::WriteAllLines(
    $path,
    $checksums,
    [Text.UTF8Encoding]::new($false))
Get-Item -LiteralPath $path
