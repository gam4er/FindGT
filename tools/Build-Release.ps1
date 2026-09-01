[CmdletBinding()]
param(
    [string]$ProductVersion = "1.0.0",
    [string]$Configuration = "Release",
    [string]$Platform = "x64",
    [switch]$SkipTests
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$root = Split-Path -Parent $PSScriptRoot
$vswhere = Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio\Installer\vswhere.exe"
if (-not (Test-Path -LiteralPath $vswhere)) {
    throw "vswhere.exe was not found."
}

$visualStudio = & $vswhere -latest -products * `
    -requires Microsoft.Component.MSBuild -property installationPath
if ([string]::IsNullOrWhiteSpace($visualStudio)) {
    throw "Visual Studio with MSBuild was not found."
}

$vcvars = Join-Path $visualStudio "VC\Auxiliary\Build\vcvars64.bat"
$nuget = Get-Command nuget.exe -ErrorAction SilentlyContinue |
    Select-Object -First 1 -ExpandProperty Source
if ([string]::IsNullOrWhiteSpace($nuget)) {
    $wingetPackages = Join-Path $env:LOCALAPPDATA "Microsoft\WinGet\Packages"
    $nuget = Get-ChildItem $wingetPackages -Directory `
        -Filter "Microsoft.NuGet_*" -ErrorAction SilentlyContinue |
        ForEach-Object {
            Get-ChildItem $_.FullName -Filter nuget.exe -File `
                -ErrorAction SilentlyContinue
        } |
        Select-Object -First 1 -ExpandProperty FullName
}
if ([string]::IsNullOrWhiteSpace($nuget)) {
    throw "nuget.exe was not found."
}

Push-Location $root
try {
    & $nuget restore FindGT.sln -NonInteractive
    if ($LASTEXITCODE -ne 0) {
        throw "NuGet restore failed with exit code $LASTEXITCODE."
    }

    & dotnet restore FindGT.Setup\FindGT.Setup.wixproj --verbosity quiet
    if ($LASTEXITCODE -ne 0) {
        throw "WiX SDK restore failed with exit code $LASTEXITCODE."
    }
    & dotnet msbuild FindGT.Setup\FindGT.Setup.wixproj `
        -target:AcceptEula -property:EulaId=wix7 -verbosity:quiet
    if ($LASTEXITCODE -ne 0) {
        throw "WiX EULA acceptance failed with exit code $LASTEXITCODE."
    }

    $commandFile = Join-Path ([IO.Path]::GetTempPath()) (
        "findgt-build-" + [Guid]::NewGuid().ToString("N") + ".cmd")
    try {
        [IO.File]::WriteAllLines(
            $commandFile,
            @(
                "@echo off",
                "call `"$vcvars`" >nul",
                "if errorlevel 1 exit /b %errorlevel%",
                ("msbuild `"FindGT.sln`" /m /nologo /verbosity:minimal " +
                    "/p:Configuration=$Configuration /p:Platform=$Platform " +
                    "/p:ProductVersion=$ProductVersion")
            ),
            [Text.Encoding]::ASCII)
        & $env:ComSpec /d /c $commandFile
        $buildExitCode = $LASTEXITCODE
    }
    finally {
        if (Test-Path -LiteralPath $commandFile) {
            Remove-Item -LiteralPath $commandFile -Force
        }
    }
    if ($buildExitCode -ne 0) {
        throw "MSBuild failed with exit code $buildExitCode."
    }

    if (-not $SkipTests) {
        $vstest = Join-Path $visualStudio (
            "Common7\IDE\CommonExtensions\Microsoft\TestWindow\vstest.console.exe")
        & $vstest "FindGT.Tests\bin\x64\$Configuration\FindGT.Tests.dll" `
            /Platform:x64
        if ($LASTEXITCODE -ne 0) {
            throw "Tests failed with exit code $LASTEXITCODE."
        }
    }

    $msi = "FindGT.Setup\bin\x64\$Configuration\FindGT-$ProductVersion-x64.msi"
    $wix = Get-Command wix.exe -ErrorAction SilentlyContinue |
        Select-Object -First 1 -ExpandProperty Source
    if ([string]::IsNullOrWhiteSpace($wix)) {
        $installedWix = "C:\Program Files\WiX Toolset v7.0\bin\wix.exe"
        if (Test-Path -LiteralPath $installedWix) {
            $wix = $installedWix
        }
    }
    if ([string]::IsNullOrWhiteSpace($wix)) {
        $packagesRoot = if ($env:NUGET_PACKAGES) {
            $env:NUGET_PACKAGES
        }
        else {
            Join-Path $env:USERPROFILE ".nuget\packages"
        }
        $wix = Get-ChildItem (
            Join-Path $packagesRoot "wixtoolset.sdk\7.0.0\tools\net472\x64"
        ) -Filter wix.exe -File -ErrorAction SilentlyContinue |
            Select-Object -First 1 -ExpandProperty FullName
    }
    if ([string]::IsNullOrWhiteSpace($wix)) {
        throw "wix.exe 7.0.0 was not found."
    }
    & $wix msi validate $msi
    if ($LASTEXITCODE -ne 0) {
        throw "MSI validation failed with exit code $LASTEXITCODE."
    }

    & "$PSScriptRoot\Assert-Msi.ps1" -MsiPath $msi
}
finally {
    Pop-Location
}
