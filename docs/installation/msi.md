# Установка MSI

## Пакет

`FindGT-x.y.z-x64.msi` собирается WiX Toolset 7.0.0 как per-machine package.
Publisher: `Родченко Александр`. Требуются elevation и .NET Framework 4.8.
Текущие artifacts unsigned.

Сборка:

```powershell
.\tools\Build-Release.ps1 -ProductVersion 1.0.0
```

## Properties

| Property | Default | Назначение |
| --- | --- | --- |
| START_SERVICE | 1 | Запустить service после install |
| ANALYZE_EXISTING_SESSIONS | 1 | Startup reconciliation |
| ENABLE_OPERATIONAL_SINK | 1 | Полный Operational output |
| SECURITY_SINK_MODE | SuspiciousOnly | Off/SuspiciousOnly/All |
| ENABLE_JSON_SINK | 0 | Protected JSONL |
| POWERFUL_ONLY | 0 | Анализировать только powerful sessions |
| PRESERVE_CONFIG_ON_UNINSTALL | 1 | Сохранить config |
| PRESERVE_STATE_ON_UNINSTALL | 1 | Сохранить state/logs |

Interactive UI меняет те же properties. Silent install:

```powershell
msiexec.exe /i .\FindGT-1.0.0-x64.msi /qn `
  START_SERVICE=1 ANALYZE_EXISTING_SESSIONS=1 `
  SECURITY_SINK_MODE=SuspiciousOnly ENABLE_JSON_SINK=0 POWERFUL_ONLY=0 `
  /L*v .\FindGT-install.log
```

## Установленные объекты

- `%ProgramFiles%\FindGT`: CLI, service, Core/Eventing, dependencies и resources.
- `%ProgramData%\FindGT\Config`: config.
- `%ProgramData%\FindGT\State`: bookmark.
- `%ProgramData%\FindGT\Logs`: optional JSONL.
- Service `FindGT`: LocalSystem, automatic delayed start.
- Operational provider/channel и Authz Security source.

ProgramData получает protected DACL: SYSTEM и Builtin Administrators — Full
Control, inheritance для дочерних объектов; обычные Users не добавляются.

## Repair и uninstall

```powershell
msiexec.exe /fa .\FindGT-1.0.0-x64.msi /qn /L*v .\FindGT-repair.log

msiexec.exe /x .\FindGT-1.0.0-x64.msi /qn `
  PRESERVE_CONFIG_ON_UNINSTALL=1 PRESERVE_STATE_ON_UNINSTALL=1 `
  /L*v .\FindGT-uninstall.log
```

Для полного удаления данных задайте обе preserve properties в `0`. Cleanup не
выполняется во время major upgrade.

## Проверка без установки

```powershell
.\tools\Assert-Msi.ps1 .\FindGT.Setup\bin\x64\Release\FindGT-1.0.0-x64.msi
```

`tools\Smoke-Install.ps1` предназначен только для disposable elevated
Windows runner/VM; на рабочем хосте автоматически не запускается.
