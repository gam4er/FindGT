[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("preflight", "deploy", "collect", "uninstall")]
    [string]$Action,
    [Parameter(Mandatory = $true)]
    [string]$Victim,
    [string]$MsiPath,
    [string]$EvidenceDirectory = "lab-evidence",
    [datetime]$SinceUtc = [datetime]::UtcNow.AddHours(-2),
    [PSCredential]$Credential
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

if ($null -eq $Credential) {
    if ($env:FINDGT_LAB_USERNAME -and $env:FINDGT_LAB_PASSWORD) {
        $securePassword = ConvertTo-SecureString $env:FINDGT_LAB_PASSWORD `
            -AsPlainText -Force
        $Credential = [PSCredential]::new(
            $env:FINDGT_LAB_USERNAME,
            $securePassword)
    }
    elseif ([Environment]::UserInteractive) {
        $Credential = Get-Credential -Message (
            "Enter the authorized lab administrator for $Victim")
    }
    else {
        throw "Lab credential is required."
    }
}

$evidence = [IO.Path]::GetFullPath($EvidenceDirectory)
New-Item -ItemType Directory -Path $evidence -Force | Out-Null
$session = New-PSSession -ComputerName $Victim -Credential $Credential
try {
    switch ($Action) {
        "preflight" {
            $result = Invoke-Command -Session $session -ScriptBlock {
                $auditLogon = & auditpol.exe /get /subcategory:"Logon" /r
                if ($LASTEXITCODE -ne 0) {
                    throw "auditpol Logon query failed with exit code $LASTEXITCODE."
                }
                $auditObjectAccess = & auditpol.exe /get `
                    /category:"Object Access" /r
                if ($LASTEXITCODE -ne 0) {
                    throw "auditpol Object Access query failed with exit code $LASTEXITCODE."
                }
                $frameworkRelease = Get-ItemPropertyValue `
                    "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full" `
                    -Name Release
                [PSCustomObject]@{
                    ComputerName = $env:COMPUTERNAME
                    Os = (Get-CimInstance Win32_OperatingSystem).Caption
                    OsVersion = (Get-CimInstance Win32_OperatingSystem).Version
                    FrameworkRelease = $frameworkRelease
                    Domain = (Get-CimInstance Win32_ComputerSystem).Domain
                    ServiceExists = $null -ne (
                        Get-Service FindGT -ErrorAction SilentlyContinue)
                    AuditLogon = ($auditLogon | Out-String).Trim()
                    AuditObjectAccess = ($auditObjectAccess | Out-String).Trim()
                }
            }
            $result | ConvertTo-Json -Depth 5 |
                Set-Content (Join-Path $evidence "preflight.json") -Encoding utf8
        }
        "deploy" {
            if ([string]::IsNullOrWhiteSpace($MsiPath) -or
                -not (Test-Path -LiteralPath $MsiPath -PathType Leaf)) {
                throw "A built MSI is required for deploy."
            }

            $remoteMsi = "C:\Windows\Temp\FindGT-x64.msi"
            Copy-Item -LiteralPath (Resolve-Path $MsiPath).Path `
                -Destination $remoteMsi -ToSession $session
            $result = Invoke-Command -Session $session -ScriptBlock {
                param($Msi)
                $arguments = @(
                    "/i", "`"$Msi`"", "/qn",
                    "START_SERVICE=1",
                    "ANALYZE_EXISTING_SESSIONS=1",
                    "SECURITY_SINK_MODE=SuspiciousOnly",
                    "ENABLE_JSON_SINK=0",
                    "/L*v", "C:\Windows\Temp\FindGT-install.log"
                )
                $process = Start-Process msiexec.exe `
                    -ArgumentList $arguments -Wait -PassThru
                if ($process.ExitCode -notin 0, 3010) {
                    throw "MSI install failed with exit code $($process.ExitCode)."
                }

                $service = Get-CimInstance Win32_Service -Filter "Name='FindGT'"
                [PSCustomObject]@{
                    ExitCode = $process.ExitCode
                    ServiceState = $service.State
                    ServiceStartMode = $service.StartMode
                    ServiceAccount = $service.StartName
                    OperationalLog = $null -ne (
                        Get-WinEvent -ListLog "FindGT/Operational" `
                            -ErrorAction SilentlyContinue)
                    ConfigPath = Test-Path (
                        "$env:ProgramData\FindGT\Config\FindGT.settings.json")
                }
            } -ArgumentList $remoteMsi
            $result | ConvertTo-Json -Depth 5 |
                Set-Content (Join-Path $evidence "deploy.json") -Encoding utf8
            Write-Host (
                "Deployment complete. Do not create a new forged logon until " +
                "the explicit collection checkpoint is announced.")
        }
        "collect" {
            $result = Invoke-Command -Session $session -ScriptBlock {
                param($StartTime)

                function Convert-EventData {
                    param([System.Diagnostics.Eventing.Reader.EventRecord]$Record)
                    [xml]$xml = $Record.ToXml()
                    $values = @{}
                    foreach ($item in $xml.Event.EventData.Data) {
                        $values[$item.GetAttribute("Name")] = $item.InnerText
                    }
                    return $values
                }

                $operational = Get-WinEvent -FilterHashtable @{
                    LogName = "FindGT/Operational"
                    StartTime = $StartTime
                } -ErrorAction SilentlyContinue | ForEach-Object {
                    [PSCustomObject]@{
                        RecordId = $_.RecordId
                        TimeCreatedUtc = $_.TimeCreated.ToUniversalTime()
                        EventId = $_.Id
                        Payload = if ($_.Properties.Count -gt 0) {
                            [string]$_.Properties[0].Value
                        } else { $null }
                    }
                }

                $logons = Get-WinEvent -FilterHashtable @{
                    LogName = "Security"
                    Id = 4624
                    StartTime = $StartTime
                } -ErrorAction SilentlyContinue | ForEach-Object {
                    $data = Convert-EventData $_
                    [PSCustomObject]@{
                        RecordId = $_.RecordId
                        TimeCreatedUtc = $_.TimeCreated.ToUniversalTime()
                        TargetUserSid = $data.TargetUserSid
                        TargetUserName = $data.TargetUserName
                        TargetDomainName = $data.TargetDomainName
                        TargetLogonId = $data.TargetLogonId
                        LogonType = $data.LogonType
                        AuthenticationPackageName =
                            $data.AuthenticationPackageName
                        WorkstationName = $data.WorkstationName
                        IpAddress = $data.IpAddress
                    }
                }

                $securityFindGt = Get-WinEvent -FilterHashtable @{
                    LogName = "Security"
                    ProviderName = "FindGT"
                    StartTime = $StartTime
                } -ErrorAction SilentlyContinue | ForEach-Object {
                    [PSCustomObject]@{
                        RecordId = $_.RecordId
                        TimeCreatedUtc = $_.TimeCreated.ToUniversalTime()
                        EventId = $_.Id
                        Message = $_.Message
                    }
                }

                [PSCustomObject]@{
                    Operational = @($operational)
                    Logons4624 = @($logons)
                    SecurityFindGT = @($securityFindGt)
                    Service = Get-CimInstance Win32_Service `
                        -Filter "Name='FindGT'" |
                        Select-Object Name, State, StartMode, StartName
                }
            } -ArgumentList $SinceUtc

            $result | ConvertTo-Json -Depth 12 |
                Set-Content (Join-Path $evidence "events.json") -Encoding utf8
            Write-Host (
                "Evidence collected. Correlate unique full LUIDs and AnalysisIds " +
                "before classifying legitimate and forged sessions.")
        }
        "uninstall" {
            $remoteMsi = "C:\Windows\Temp\FindGT-x64.msi"
            $result = Invoke-Command -Session $session -ScriptBlock {
                param($Msi)
                $arguments = @(
                    "/x", "`"$Msi`"", "/qn",
                    "PRESERVE_CONFIG_ON_UNINSTALL=1",
                    "PRESERVE_STATE_ON_UNINSTALL=1",
                    "/L*v", "C:\Windows\Temp\FindGT-uninstall.log"
                )
                $process = Start-Process msiexec.exe `
                    -ArgumentList $arguments -Wait -PassThru
                if ($process.ExitCode -notin 0, 3010) {
                    throw "MSI uninstall failed with exit code $($process.ExitCode)."
                }
                [PSCustomObject]@{
                    ExitCode = $process.ExitCode
                    ServiceExists = $null -ne (
                        Get-Service FindGT -ErrorAction SilentlyContinue)
                    ConfigPreserved = Test-Path (
                        "$env:ProgramData\FindGT\Config\FindGT.settings.json")
                }
            } -ArgumentList $remoteMsi
            $result | ConvertTo-Json -Depth 5 |
                Set-Content (Join-Path $evidence "uninstall.json") -Encoding utf8
        }
    }
}
finally {
    Remove-PSSession $session
    if ($env:FINDGT_LAB_PASSWORD) {
        Remove-Item Env:FINDGT_LAB_PASSWORD
    }
}
