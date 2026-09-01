# Troubleshooting

## Базовая диагностика

```powershell
Get-CimInstance Win32_Service -Filter "Name='FindGT'" |
  Select-Object Name, State, StartMode, StartName, PathName

Get-WinEvent -LogName "FindGT/Operational" -MaxEvents 50 |
  Select-Object TimeCreated, Id, LevelDisplayName, Message
```

Service account должен быть `LocalSystem`, start mode — Auto, registry
`DelayedAutoStart` — 1.

## Нет 4624

Проверьте read-only состояние:

```powershell
auditpol.exe /get /subcategory:"Logon"
Get-WinEvent -FilterHashtable @{LogName="Security"; Id=4624} -MaxEvents 5
```

FindGT не включает auditing автоматически. При недоступной subscription служба
остаётся активной и использует reconciliation; это не гарантирует захват
короткоживущих sessions.

## Нет Security summary

Operational остаётся источником полного результата. Проверьте:

```powershell
Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security\FindGT"
auditpol.exe /get /category:"Object Access"
```

Authz output зависит от существующей audit policy. Не изменяйте domain policy
автоматически ради теста.

## Unknown / DC unavailable

`Unknown` — безопасный результат, не Clean. Проверьте DNS/time/DC:

```powershell
nltest.exe /dsgetdc:CONTOSO.COM
w32tm.exe /query /status
Test-NetConnection DC01.contoso.com -Port 389
```

Не добавляйте silent fallback к пустому reference.

## Bookmark

При `BookmarkInvalid` сохраните diagnostics, остановите service и переместите
конкретный файл `%ProgramData%\FindGT\State\Security.bookmark.xml` в quarantine.
После старта служба выполнит полный reconciliation. Не удаляйте весь ProgramData.

## Queue pressure

Event 1012 означает bounded overflow. Проверьте DC latency и количество 4624.
Не увеличивайте capacity без измерения memory/throughput; reconciliation уже
покрывает потерянные active sessions.

## MSI

Используйте verbose logs и table assertion:

```powershell
msiexec.exe /i .\FindGT-1.0.0-x64.msi /qn START_SERVICE=0 `
  /L*v .\FindGT-install.log
.\tools\Assert-Msi.ps1 .\FindGT-1.0.0-x64.msi
```
