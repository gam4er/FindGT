[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string]$OldMsiPath,
    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string]$NewMsiPath,
    [string]$OldInstallLog = "$env:TEMP\FindGT-old-install.log",
    [string]$UpgradeLog = "$env:TEMP\FindGT-upgrade.log",
    [string]$UninstallLog = "$env:TEMP\FindGT-upgrade-uninstall.log"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Smoke-Upgrade.ps1 requires an elevated process."
}

$oldMsi = (Resolve-Path -LiteralPath $OldMsiPath).Path
$newMsi = (Resolve-Path -LiteralPath $NewMsiPath).Path
$oldInstalled = $false
$newInstalled = $false
try {
    $process = Start-Process msiexec.exe -Wait -PassThru -ArgumentList @(
        "/i", "`"$oldMsi`"", "/qn",
        "START_SERVICE=0",
        "/L*v", "`"$OldInstallLog`""
    )
    if ($process.ExitCode -notin 0, 3010) {
        throw "Old MSI install failed with exit code $($process.ExitCode)."
    }
    $oldInstalled = $true

    $config = "$env:ProgramData\FindGT\Config\FindGT.settings.json"
    $content = Get-Content -LiteralPath $config -Raw
    $updatedContent = $content.Replace(
        '"ReconciliationIntervalSeconds": 60',
        '"ReconciliationIntervalSeconds": 61')
    if ($updatedContent -eq $content) {
        throw "Unable to create a configuration-preservation sentinel."
    }
    [IO.File]::WriteAllText(
        $config,
        $updatedContent,
        [Text.UTF8Encoding]::new($false))
    $configHash = (Get-FileHash $config -Algorithm SHA256).Hash

    $process = Start-Process msiexec.exe -Wait -PassThru -ArgumentList @(
        "/i", "`"$newMsi`"", "/qn",
        "START_SERVICE=0",
        "/L*v", "`"$UpgradeLog`""
    )
    if ($process.ExitCode -notin 0, 3010) {
        throw "MSI major upgrade failed with exit code $($process.ExitCode)."
    }
    $newInstalled = $true
    $oldInstalled = $false

    if ((Get-FileHash $config -Algorithm SHA256).Hash -ne $configHash) {
        throw "Major upgrade overwrote the existing configuration."
    }
    $service = Get-CimInstance Win32_Service -Filter "Name='FindGT'"
    if ($null -eq $service -or $service.StartName -ne "LocalSystem") {
        throw "FindGT service is invalid after major upgrade."
    }
}
finally {
    if ($newInstalled) {
        $process = Start-Process msiexec.exe -Wait -PassThru -ArgumentList @(
            "/x", "`"$newMsi`"", "/qn",
            "PRESERVE_CONFIG_ON_UNINSTALL=0",
            "PRESERVE_STATE_ON_UNINSTALL=0",
            "/L*v", "`"$UninstallLog`""
        )
        if ($process.ExitCode -notin 0, 3010) {
            throw "New MSI uninstall failed with exit code $($process.ExitCode)."
        }
    }
    elseif ($oldInstalled) {
        $process = Start-Process msiexec.exe -Wait -PassThru -ArgumentList @(
            "/x", "`"$oldMsi`"", "/qn",
            "PRESERVE_CONFIG_ON_UNINSTALL=0",
            "PRESERVE_STATE_ON_UNINSTALL=0",
            "/L*v", "`"$UninstallLog`""
        )
        if ($process.ExitCode -notin 0, 3010) {
            throw "Old MSI uninstall failed with exit code $($process.ExitCode)."
        }
    }
}
