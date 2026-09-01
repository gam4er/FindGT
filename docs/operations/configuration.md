# Конфигурация

Файл: `%ProgramData%\FindGT\Config\FindGT.settings.json`.

Canonical default находится в
[`FindGT.Service/FindGT.settings.json`](../../FindGT.Service/FindGT.settings.json).

## Основные значения

- `SchemaVersion`: только 1.
- `EnabledLogonTypes`: default `[3, 10]`; поддерживаются 2, 3, 4, 5, 9, 10.
- `AnalyzeExistingSessionsOnStart`: default `true`.
- `ReconciliationIntervalSeconds`: 10–86400, default 60.
- `Queue.Capacity`: 1–65536, default 1024.
- `Queue.WorkerCount`: 1–8, default 1.
- `RetryDelaysMilliseconds`: неубывающий массив, начинается с 0.

## PowerfulOnly

Default `Enabled=false`. Стандартные matches:

- user RID 500;
- group RID 512, 518, 519;
- exact SID `S-1-5-32-544`;
- `AdditionalSids`.

RID извлекается из binary SID, не через string suffix. Deny-only group также
считается match. Non-powerful session получает `NotEvaluated`.

## Output

- Operational включён по умолчанию.
- Security mode: `Off`, `SuspiciousOnly`, `All`.
- JSON выключен; directory поддерживает environment variables.
- Operational или JSON full-result sink должен быть включён.

## Invalid config

Invalid JSON/schema/range/SID не включает risky options. Служба использует
safe defaults (`PowerfulOnly=false`, `JSON=false`) и пишет
`ConfigurationInvalid`. Audit policy не меняется.

После изменения config перезапустите service:

```powershell
Restart-Service FindGT
```
