# Session notification и reconciliation

## Event 4624

`SecurityEventLogSource` использует `EventLogWatcher` и запрос:

```text
*[System[Provider[@Name='Microsoft-Windows-Security-Auditing'] and EventID=4624]]
```

`Event4624Parser` читает `EventData/Data` только по атрибуту `Name`. Фиксированные
позиции `Properties[n]` не используются. `TargetLogonId` разбирается как полный
unsigned 64-bit LUID.

Event metadata сохраняет SID/name/domain, logon type, event auth package,
workstation/IP/process и linked logon ID. Поле event auth package может быть
`Negotiate`; окончательное решение Kerberos принимает analyzer по LSA.

## Queue и retry

Callback выполняет parse и non-blocking enqueue. Default capacity — 1024,
worker count — 1. При overflow событие не считается завершённым, устанавливается
`DegradedQueuePressure` и планируется reconciliation.

Retry delays: 0, 250, 1000, 3000 и 10000 ms. Они закрывают гонку между появлением
4624 и доступностью LSA session. Исчезнувшая session завершается как
`Unknown / SessionExpiredBeforeAnalysis`.

## Bookmark

Путь: `%ProgramData%\FindGT\State\Security.bookmark.xml`.

Bookmark сохраняется атомарно только после успешной записи terminal result в
full-result sink. Семантика — at least once: crash может повторить событие, а
boot-aware dedupe должен выдержать replay.

.NET Framework 4.8 не публикует XML constructor/property `EventBookmark`.
Изолированный `EventBookmarkCompatibility` использует проверенную internal
framework surface и fail-fast `PlatformNotSupportedException`; BinaryFormatter
не используется.

При invalid bookmark сначала используется last-known-good `.bak`; если он тоже
непригоден, служба replay-ит 4624 за последние 24 часа, ставит
`DegradedBookmark`, выполняет полный reconciliation и продолжает работу.

## Reconciliation

Startup snapshot включён по умолчанию. Periodic interval — 60 секунд.
Дополнительный reconciliation запускается после subscription error, queue
pressure, invalid bookmark и sink failure.
