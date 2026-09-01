[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string]$MsiPath,
    [string]$InstallLog = "$env:TEMP\FindGT-install.log",
    [string]$RepairLog = "$env:TEMP\FindGT-repair.log",
    [string]$UninstallLog = "$env:TEMP\FindGT-uninstall.log"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Smoke-Install.ps1 requires an elevated process."
}

$msi = (Resolve-Path -LiteralPath $MsiPath).Path
$installed = $false
try {
    $arguments = @(
        "/i", "`"$msi`"", "/qn",
        "START_SERVICE=0",
        "ANALYZE_EXISTING_SESSIONS=1",
        "SECURITY_SINK_MODE=SuspiciousOnly",
        "ENABLE_JSON_SINK=0",
        "/L*v", "`"$InstallLog`""
    )
    $process = Start-Process msiexec.exe -ArgumentList $arguments `
        -Wait -PassThru
    if ($process.ExitCode -notin 0, 3010) {
        throw "MSI install failed with exit code $($process.ExitCode)."
    }
    $installed = $true

    $service = Get-CimInstance Win32_Service -Filter "Name='FindGT'"
    if ($null -eq $service -or $service.StartName -ne "LocalSystem") {
        throw "FindGT service registration is invalid."
    }
    if ($service.StartMode -ne "Auto") {
        throw "FindGT service is not configured for automatic start."
    }
    $serviceKey = "HKLM:\SYSTEM\CurrentControlSet\Services\FindGT"
    if ((Get-ItemPropertyValue $serviceKey DelayedAutoStart) -ne 1) {
        throw "FindGT delayed automatic start is not configured."
    }

    $failureActions = & sc.exe qfailure FindGT
    if ($LASTEXITCODE -ne 0 -or
        ($failureActions -join "`n") -notmatch "30000" -or
        ($failureActions -join "`n") -notmatch "60000" -or
        ($failureActions -join "`n") -notmatch "300000") {
        throw "FindGT service recovery configuration is invalid."
    }

    foreach ($path in @(
        "$env:ProgramFiles\FindGT\FindGT.exe",
        "$env:ProgramFiles\FindGT\FindGT.Service.exe",
        "$env:ProgramFiles\FindGT\FindGT.Core.dll",
        "$env:ProgramFiles\FindGT\FindGT.Eventing.dll",
        "$env:ProgramData\FindGT\Config\FindGT.settings.json"
    )) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "Installed payload is missing: $path"
        }
    }

    if (-not (Test-Path (
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Publishers\" +
        "{24f97934-34df-4f64-b07d-5744f7d46eed}"))) {
        throw "FindGT Operational provider is not registered."
    }
    if (-not (Test-Path (
        "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security\FindGT"))) {
        throw "FindGT Authz Security source is not registered."
    }

    $configPath = "$env:ProgramData\FindGT\Config\FindGT.settings.json"
    $configHash = (Get-FileHash -LiteralPath $configPath -Algorithm SHA256).Hash
    $arguments = @(
        "/fa", "`"$msi`"", "/qn",
        "START_SERVICE=0",
        "/L*v", "`"$RepairLog`""
    )
    $process = Start-Process msiexec.exe -ArgumentList $arguments `
        -Wait -PassThru
    if ($process.ExitCode -notin 0, 3010) {
        throw "MSI repair failed with exit code $($process.ExitCode)."
    }
    if ((Get-FileHash -LiteralPath $configPath -Algorithm SHA256).Hash -ne
        $configHash) {
        throw "MSI repair overwrote the existing configuration."
    }
}
finally {
    if ($installed) {
        $arguments = @(
            "/x", "`"$msi`"", "/qn",
            "PRESERVE_CONFIG_ON_UNINSTALL=0",
            "PRESERVE_STATE_ON_UNINSTALL=0",
            "/L*v", "`"$UninstallLog`""
        )
        $process = Start-Process msiexec.exe -ArgumentList $arguments `
            -Wait -PassThru
        if ($process.ExitCode -notin 0, 3010) {
            throw "MSI uninstall failed with exit code $($process.ExitCode)."
        }
    }
}

if (Get-Service FindGT -ErrorAction SilentlyContinue) {
    throw "FindGT service remains after uninstall."
}
if (Test-Path "$env:ProgramFiles\FindGT") {
    throw "FindGT Program Files directory remains after uninstall."
}
if (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security\FindGT") {
    throw "FindGT Authz Security source remains after uninstall."
}
if (Test-Path (
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Publishers\" +
    "{24f97934-34df-4f64-b07d-5744f7d46eed}")) {
    throw "FindGT Operational provider remains after uninstall."
}
