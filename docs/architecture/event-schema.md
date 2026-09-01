# Event schema

## Operational provider

- Provider: `FindGT`
- Provider GUID: `{24F97934-34DF-4F64-B07D-5744F7D46EED}`
- Channel: `FindGT/Operational`
- Payload: одна bounded UTF-16 JSON string
- Schema version: 1

| ID | Level | Значение |
| ---: | --- | --- |
| 1000 | Information | ServiceStarted |
| 1001 | Information | SessionAnalysisClean |
| 1002 | Warning | SessionAnalysisSuspicious |
| 1003 | Warning | SessionAnalysisUnknown |
| 1004 | Error | SessionAnalysisError |
| 1005 | Information | SessionSkippedNotPowerful |
| 1006 | Information | SessionSkippedByPolicy |
| 1010 | Warning | SecuritySubscriptionError |
| 1011 | Information | SessionRecoveredByReconciliation |
| 1012 | Warning | QueuePressure |
| 1013 | Warning | SecuritySinkUnavailable |
| 1014 | Warning | BookmarkInvalid |
| 1015 | Warning | DomainControllerUnavailable |
| 1016 | Warning | ConfigurationInvalid |
| 1020 | Information | ServiceStopped |

Analysis payload содержит `AnalysisId`, timestamp, computer/boot IDs, trigger,
full LUID, LSA identity, reference status, group counts, PowerfulOnly state,
verdict/status/reason, rule evidence, duration и retry count.

## Verdict

| Verdict | Смысл |
| --- | --- |
| Clean | Reference получен, suspicious rules отсутствуют |
| Suspicious | Найдено авторизационное противоречие |
| Unknown | Данных недостаточно; Clean запрещён |
| NotEvaluated | Session пропущена policy |
| Error | Нарушен internal invariant или данные некорректны |

## Rules

FGT001–FGT010 охватывают token-only/reference-only groups, user SID в groups,
identity mismatch, missing/disabled account, suspicious SID history,
contradictory group attributes, cross-domain inconsistency и Event-vs-LSA
mismatch. FGT002 информационный и сам по себе не делает verdict Suspicious.

## Security

Authz source name: `FindGT`; audit message ID: 2000. Default mode —
`SuspiciousOnly`. Security payload содержит summary и `AnalysisId`, но не полный
group list. Наличие записи зависит от уже действующего Object Access auditing;
FindGT audit policy не меняет.
