# Авторизованная лабораторная проверка

Live test выполняется только на перечисленных VMware VMs после snapshots и
явного разрешения владельца. Golden Ticket создаёт/активирует пользователь;
FindGT automation не генерирует ticket и не хранит KRBTGT material.

## Private dossier

Hostnames, VMX paths, credentials и test identities заполняются в локальном
`lab-credentials.md` вне Git. Не переносите secrets, hashes, ticket caches или
raw Security EVTX в repository/workflow artifacts.

## Порядок

1. `preflight`: OS/domain/.NET/audit state и transport.
2. Собрать MSI и записать SHA-256.
3. Snapshot DC, attacker и victim.
4. `deploy`: установить MSI на Windows Server 2019 victim.
5. Проверить LocalSystem/service/provider/source/config ACL.
6. Startup reconciliation должен увидеть уже существующую forged session.
7. Legitimate administrator session должна анализироваться отдельно.
8. Остановиться на checkpoint; пользователь выполняет второй forged logon.
9. `collect`: получить настоящий 4624 и FindGT events.
10. Сопоставить два forged full LUID/AnalysisId и legitimate LUID.
11. Проверить PowerfulOnly и DC unavailable → `Unknown`.
12. `uninstall`, cleanup/revert snapshots, rotation credentials.

Основной helper:

```powershell
$credential = Get-Credential "CONTOSO\LabAdmin"
.\tools\Invoke-LabValidation.ps1 -Action preflight `
  -Victim "VICTIM.contoso.com" -Credential $credential
```

Deploy/collect:

```powershell
.\tools\Invoke-LabValidation.ps1 -Action deploy `
  -Victim "VICTIM.contoso.com" -Credential $credential `
  -MsiPath ".\FindGT.Setup\bin\x64\Release\FindGT-1.0.0-x64.msi"

# Только после пользовательского Golden Ticket checkpoint:
.\tools\Invoke-LabValidation.ps1 -Action collect `
  -Victim "VICTIM.contoso.com" -Credential $credential `
  -SinceUtc ([datetime]::UtcNow.AddMinutes(-30))
```

## SMB/CIM fallback

Если WinRM недоступен, MSI можно скопировать через admin share и запустить через
CIM. Password остаётся внутри `PSCredential`.

```powershell
$drive = New-PSDrive -Name FGT -PSProvider FileSystem `
  -Root "\\VICTIM.contoso.com\C$" -Credential $credential
Copy-Item .\FindGT-1.0.0-x64.msi `
  "$($drive.Name):\Windows\Temp\FindGT-x64.msi"
$cim = New-CimSession -ComputerName "VICTIM.contoso.com" `
  -Credential $credential
Invoke-CimMethod -CimSession $cim -ClassName Win32_Process `
  -MethodName Create -Arguments @{
    CommandLine = "msiexec.exe /i C:\Windows\Temp\FindGT-x64.msi /qn " +
      "START_SERVICE=1 /L*v C:\Windows\Temp\FindGT-install.log"
  }
```

PsExec — последний interactive fallback; не используйте `-p`:

```powershell
psexec.exe \\VICTIM.contoso.com -u CONTOSO\LabAdmin -h -s `
  msiexec.exe /i C:\Windows\Temp\FindGT-x64.msi /qn START_SERVICE=1
```

## Acceptance

- Existing forged session: `TriggerSource=StartupReconciliation`, Suspicious.
- New forged session: `TriggerSource=Event4624`, Suspicious.
- Два forged LUID различны и не dedupe-ятся друг с другом.
- Legitimate admin имеет отдельный AnalysisId; при доступном reference — Clean.
- Operational содержит full records; Security summaries коррелируют по AnalysisId.
- Reference outage никогда не создаёт Clean.
