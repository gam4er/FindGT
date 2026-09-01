# FindGT — детектор аномалий членства для Golden Ticket

> Версии README по языкам:
>
> | Язык    | Файл                         |
> | ------- | ---------------------------- |
> | English | [README.md](README.md)       |
> | Russian | [README.ru.md](README.ru.md) |
> | Greek   | [README.el.md](README.el.md) |
>
> Файлы README на всех языках должны быть эквивалентны по смыслу — см. [AGENTS.md](AGENTS.md).

FindGT проверяет **Kerberos‑сессии входа** Windows и сравнивает членство в группах,
**заявленное токеном каждой сессии**, с **авторитетным членством**, которое для этого
пользователя сообщает контроллер домена. Golden Ticket подделывает TGT с произвольными
SID групп (`Domain Admins`, `Enterprise Admins`, `Schema Admins` и т.п.); такие поддельные
группы есть в токене сессии, но **отсутствуют** в авторитетном источнике — именно это и
выявляет FindGT.

> Статус: production-oriented реализация службы и MSI готова к лабораторной проверке;
> end-to-end подтверждение настоящим Golden Ticket ещё не выполнено. Исследовательские
> CLI-команды сохранены отдельно. Часть исходного token/session кода основана на
> [GhostPack/Koh](https://github.com/GhostPack/Koh).

## Почему хосты доверяют Golden Ticket

В Kerberos доверие строится вокруг валидной криптографии и сервисных билетов, выданных KDC.

1. Атакующий подделывает TGT (Golden Ticket) и помещает фейковое членство в PAC.
2. Атакующий отправляет этот TGT на KDC в запросе TGS к целевому сервису.
3. KDC проверяет криптографическую валидность билета (доверительный путь KRBTGT).
4. Если криптография валидна, KDC выпускает сервисный билет и переносит PAC-данные авторизации из входящего TGT, не перестраивая членство по AD на этом TGS-этапе.
5. Атакующий предъявляет сервисный билет хосту-жертве.
6. На хосте LSASS проверяет криптографию сервисного билета.
7. LSASS материализует данные идентичности/групп в токене сессии.
8. Поддельное членство приходит на хост как «доверенный» артефакт авторизации.
9. Мы видим это в token groups созданной сессии.

```mermaid
---
config:
  htmlLabels: false
  markdownAutoWrap: true
  flowchart:
    useMaxWidth: false
    wrappingWidth: 300
    nodeSpacing: 50
    rankSpacing: 60
---
flowchart TD
  A["`1. Атакующий подделывает TGT и добавляет в PAC фиктивные группы`"]
    --> B["`2. Отправка TGS-REQ контроллеру домена`"]

  B --> C["`3. KDC проверяет криптографическую целостность TGT`"]

  C --> D["`4. KDC выдаёт сервисный билет и переносит в него авторизационные данные PAC из TGT, не восстанавливая фактическое членство пользователя в группах Active Directory`"]

  D --> E["`5. Сервисный билет возвращается атакующему`"]
  E --> F["`6. TGS предъявляется целевому узлу`"]
  F --> G["`7. LSASS проверяет криптографическую целостность сервисного билета`"]
  G --> H["`8. Создаётся токен пользовательской сессии`"]
  H --> I["`9. Token Groups содержат поддельное членство в группах`"]

  A -. "`Причинно-следственная цепочка: поддельные группы из PAC попадают в Token Groups на целевом узле`" .-> I

  classDef startNode fill:#d7263d,stroke:#8f1322,color:#ffffff,stroke-width:2px;
  classDef endNode fill:#ff9f1c,stroke:#b86b00,color:#1f1300,stroke-width:2px;

  class A startNode;
  class I endNode;

  linkStyle 8 stroke:#ff3b30,stroke-width:3px;
```

Статическая SVG-версия: [SlidesAndDocs/diagrams/golden-ticket-trust-flow.svg](SlidesAndDocs/diagrams/golden-ticket-trust-flow.svg)

## Граница детектирования: наблюдаемое против зашифрованного

FindGT анализирует LSASS-сессии и token groups, потому что это практичный, наблюдаемый и более
безопасный слой детектирования на endpoint.

- Наблюдаемое: сессии входа, token groups, SID-расхождения.
- Непрактично как массовый endpoint-подход: произвольная дешифрация билетов.
- Причина безопасности: такой подход расширяет экспозицию ключевого материала и поверхность атаки.

```mermaid
---
config:
  htmlLabels: false
  markdownAutoWrap: true
  flowchart:
    useMaxWidth: false
    wrappingWidth: 300
    nodeSpacing: 50
    rankSpacing: 60
---
flowchart TB
  subgraph Observable["`Наблюдаемо на endpoint`"]
    S["`LSASS-сессии`"]
    T["`Token Groups`"]
    D["`Дифф токена против эталона`"]
  end

  subgraph Encrypted["`Зашифровано или рискованно раскрывать`"]
    K["`Зашифрованные части TGT/TGS`"]
    R["`Долгоживущие ключи KRBTGT и сервисов`"]
  end

  S --> D
  T --> D
  K -. "`избегаем массовой endpoint-дешифрации`" .-> D
  R -. "`ключевой материал держим минимально распространенным`" .-> D
```

Статическая SVG-версия: [SlidesAndDocs/diagrams/findgt-observable-boundary.svg](SlidesAndDocs/diagrams/findgt-observable-boundary.svg)

## Где FindGT сильнее / слабее

FindGT наиболее информативен в production-like AD-средах, где за время эксплуатации накопилось
реальное нетривиальное вложенное членство.

Среды с низким контрастом (сигнал слабее):

- Только дефолтный набор групп.
- Недавно развернутый домен с минимальным жизненным циклом идентичностей.
- Нет леса и нет доверенных внешних доменов.
- Небольшая глубина вложенности групп.

Если расхождения не найдены, это корректнее трактовать как «не обнаружено в текущем baseline»,
а не как криптографическое доказательство отсутствия атаки.

## Примечание по утверждениям о Mimikatz / Rubeus

Некорректно утверждать, что современные инструменты строго ограничены только "однодоменным"
членством. Текущие реализации умеют заполнять и `GroupIds`, и `ExtraSids` в
PAC/KERB_VALIDATION_INFO. Будут ли междоменный SID реально принят, определяют trust, SID
filtering и PAC validation политики конкретной среды.

Mimikatz (официальные upstream permalink):

- [kuhl_m_kerberos_pac.c @ 306bc6b #L146-L173](https://github.com/gentilkiwi/mimikatz/blob/306bc6b43099c7b698f2898401fddbded6a630c8/mimikatz/modules/kerberos/kuhl_m_kerberos_pac.c#L146-L173) — заполнение `KERB_VALIDATION_INFO`, включая `GroupIds` и `ExtraSids`.
- [kuhl_m_kerberos_pac.c @ 306bc6b #L179-L245](https://github.com/gentilkiwi/mimikatz/blob/306bc6b43099c7b698f2898401fddbded6a630c8/mimikatz/modules/kerberos/kuhl_m_kerberos_pac.c#L179-L245) — парсинг RID-групп/дефолтных групп и разбор SID в `KERB_SID_AND_ATTRIBUTES`.
- [kuhl_m_kerberos.c @ 306bc6b #L633-L640](https://github.com/gentilkiwi/mimikatz/blob/306bc6b43099c7b698f2898401fddbded6a630c8/mimikatz/modules/kerberos/kuhl_m_kerberos.c#L633-L640) — путь генерации и подписи PAC из validation info.

Rubeus (официальные upstream permalink):

- [ForgeTicket.cs @ 74215f6 #L89-L124](https://github.com/GhostPack/Rubeus/blob/74215f68ea70bd6a66c008da91bf5fe21d20b154/Rubeus/lib/ForgeTicket.cs#L89-L124) — инициализация `_KERB_VALIDATION_INFO`, базовые `GroupIds`/`ExtraSids`.
- [ForgeTicket.cs @ 74215f6 #L576-L592](https://github.com/GhostPack/Rubeus/blob/74215f68ea70bd6a66c008da91bf5fe21d20b154/Rubeus/lib/ForgeTicket.cs#L576-L592) — циклы заполнения `GroupIds` и `ExtraSids`.
- [Kerberos_PAC.cs @ 74215f6 #L681-L784](https://github.com/GhostPack/Rubeus/blob/74215f68ea70bd6a66c008da91bf5fe21d20b154/Rubeus/lib/krb_structures/pac/Ndr/Kerberos_PAC.cs#L681-L784) — структура `_KERB_VALIDATION_INFO` с полями `GroupIds` и `ExtraSids`.

## Как это работает

1. Служба сначала подписывается на Security Event 4624, затем перечисляет уже
   существующие LSA-сессии и запускает периодический reconciliation.
2. Callback разбирает поля XML по `Data/@Name`, сохраняет полный 64-bit
   `TargetLogonId` и только ставит candidate в bounded queue.
3. Worker подтверждает сессию через `LsaGetLogonSessionData`; окончательный
   Kerberos-фильтр выполняется по LSA `AuthenticationPackage`.
4. Для сессии извлекаются token group SID **вместе с attributes**. Опциональный
   `PowerfulOnly` использует структурные RID/SID checks и по умолчанию выключен.
5. Авторитетное членство запрашивается через S4U2Self; при отказе выполняется
   рекурсивный LDAP fallback. Если оба источника недоступны, verdict — `Unknown`,
   никогда не `Clean`.
6. Rule engine формирует FGT001–FGT010. Полный результат записывается в
   `FindGT/Operational`; Security summary через Authz по умолчанию создаётся
   только для `Suspicious`.

CLI и служба используют один typed analyzer. Поскольку S4U2Self запрашивает DC
заново под машинной идентичностью, Golden Ticket в пользовательской сессии не
может изменить авторитетный ответ.

## Компоненты

| Проект | Назначение | Платформа |
| --- | --- | --- |
| **FindGT** | Сохранённый Spectre.Console CLI и NRPC/S4U diagnostics. | .NET Framework 4.8, x64 |
| **FindGT.Core** | LSA/token ownership, full LUID, membership providers, PowerfulOnly, rules и typed analyzer. | .NET Framework 4.8, x64 |
| **FindGT.Eventing** | 4624 parser/watcher, bookmark, queue/dedupe и Operational/Authz/JSON sinks. | .NET Framework 4.8, x64 |
| **FindGT.Service** | Отдельный `ServiceBase` host с reconciliation, retry, health и safe shutdown. | .NET Framework 4.8, x64 |
| **FindGT.EventMessages** | Manifest и message-resource DLL для Operational и Authz Security events. | Native x64 |
| **FindGT.SetupActions** | Минимальные native MSI actions для Authz, ACL и service recovery. | Native x64 |
| **FindGT.Setup** | WiX 7 x64 per-machine MSI. | WiX Toolset 7.0.0 |
| **FindGT.Tests** | Unit tests Core/Eventing/Service/MSI contracts. | MSTest 4.3.3, x64 |
| **LsaSecretExtractor** | Отдельный research helper; в MSI не входит. | .NET Framework 4.8 |

## Windows-служба и MSI

- Service name: `FindGT`; account: `LocalSystem`; startup: Automatic (Delayed Start).
- Default logon types: 3 (Network) и 10 (RemoteInteractive).
- Конфигурация: `%ProgramData%\FindGT\Config\FindGT.settings.json`.
- Bookmark: `%ProgramData%\FindGT\State\Security.bookmark.xml`.
- Основной журнал: Applications and Services Logs → `FindGT/Operational`.
- Security output использует Authz; audit policy установщик и служба не меняют.
- JSONL выключен по умолчанию и при включении пишется в защищённый ProgramData.
- MSI unsigned до появления production certificate; проверяйте SHA-256.

Подробности: [архитектура](docs/architecture/service-architecture.md),
[MSI](docs/installation/msi.md), [конфигурация](docs/operations/configuration.md)
и [troubleshooting](docs/operations/troubleshooting.md).

## Признаки Golden Ticket

Ниже приведены рабочие артефакты, которые в реальных расследованиях помогают отличать
поддельные билеты от KDC-issued билетов. Это не «магическая кнопка», а набор сигналов,
которые лучше использовать в связке.

### Признак 1: Resource Group-представление RID 572

Для `Domain Admins` критичен контекст группы `Denied RODC Password Replication Group` (RID 572).

- В поддельном пути (golden) группа может выглядеть как обычная.
- В легитимном пути в token она приходит как `Mandatory, Resource`.

Иллюстрация:

- Golden: ![Golden Administrator](SlidesAndDocs/Pic/Golden_Administrator.png)
- Legit: ![Real Administrator](SlidesAndDocs/Pic/Real_Administrator.png)

Почему это возможно:

- В генерации PAC Mimikatz поля resource groups не заполняются:
  [kuhl_m_kerberos_pac.c#L168-L172](https://github.com/gentilkiwi/mimikatz/blob/306bc6b43099c7b698f2898401fddbded6a630c8/mimikatz/modules/kerberos/kuhl_m_kerberos_pac.c#L168-L172)
- Структура и назначение полей описаны в MS-PAC:
  [MS-PAC / KERB_VALIDATION_INFO](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/69e86ccc-85e3-41b9-b514-7d969cd0ed73)

### Признак 2: null pointer vs empty string pointer в LOGON_INFO

В wire-level NDR строковые поля (`FullName`, `LogonScript`, `ProfilePath`, `HomeDirectory`,
`HomeDirectoryDrive`, `ServerName`) в golden-билетах часто кодируются как null pointers.
В легитимном PAC при пустых значениях часто виден ненулевой pointer на пустой массив.

Важно: для network logon пустой `FullName` сам по себе нормален. Признак здесь именно
в форме представления (null pointer vs empty string pointer), а не в том, что строка пустая.

Иллюстрация (поле Full name):

- Golden: ![Golden Full name](SlidesAndDocs/Pic/Full_name_is_null.png)
- Legit: ![Real Full name](SlidesAndDocs/Pic/Full_name_Administrator.png)

Иллюстрация (поле Logon script):

- Golden: ![Golden Logon script](SlidesAndDocs/Pic/Logon_script_is_empty_string.png)
- Legit: ![Real Logon script](SlidesAndDocs/Pic/Logon_script_is_NULL.png)

Почему это происходит:

- `KERB_VALIDATION_INFO` создаётся через `LocalAlloc(LPTR, ...)`, память обнуляется:
  [kuhl_m_kerberos_pac.c#L146-L173](https://github.com/gentilkiwi/mimikatz/blob/306bc6b43099c7b698f2898401fddbded6a630c8/mimikatz/modules/kerberos/kuhl_m_kerberos_pac.c#L146-L173)
- Семантика полей описана в MS-PAC:
  [MS-PAC / KERB_VALIDATION_INFO](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/69e86ccc-85e3-41b9-b514-7d969cd0ed73)

### Признак 3: отсутствие PAC type 12 (`UPN_DNS_INFO`)

В трассах golden-билетов часто отсутствует `UPN_DNS_INFO` (type 12), тогда как в легитимном
пути KDC обычно добавляет этот буфер.

Иллюстрация (структура UPN):

- Golden: ![Golden UPN](SlidesAndDocs/Pic/No_UPN.png)
- Legit: ![Real UPN](SlidesAndDocs/Pic/UPN_exists.png)

Почему это происходит:

- Типы PAC buffer: [MS-PAC / PAC_INFO_BUFFER](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/3341cfa2-6ef5-42e0-b7bc-4544884bf399)
- Структура type 12: [MS-PAC / UPN_DNS_INFO](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/1c0d6e11-6443-4846-b744-f9f810a504eb)
- Генерация PAC в Mimikatz (без type 12):
  [kuhl_m_kerberos_pac.c#L8](https://github.com/gentilkiwi/mimikatz/blob/306bc6b43099c7b698f2898401fddbded6a630c8/mimikatz/modules/kerberos/kuhl_m_kerberos_pac.c#L8)

### Признак 4: `EffectiveName.MaximumLength = Length + 2`

При генерации golden-билета видно паттерн `MaximumLength = Length + 2` (из-за
`RtlInitUnicodeString`), тогда как в легитимном PAC часто встречается `MaximumLength = Length`.

Иллюстрация (EffectiveName):

- Golden: ![Golden +1 symbol](SlidesAndDocs/Pic/EffectiveName_and_time_is_bad.png)
- Legit: ![Real size == length](SlidesAndDocs/Pic/EffectiveName_and_time_is_OK.png)

Почему это происходит:

- Установка имени: [kuhl_m_kerberos_pac.c#L157](https://github.com/gentilkiwi/mimikatz/blob/306bc6b43099c7b698f2898401fddbded6a630c8/mimikatz/modules/kerberos/kuhl_m_kerberos_pac.c#L157)
- Поле в спецификации: [MS-PAC / EffectiveName](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/69e86ccc-85e3-41b9-b514-7d969cd0ed73)

### Признак 5: исторические поля AD выглядят неестественно

Для golden-билетов типично:

- `LogonCount = 0`
- `PasswordLastSet` выставлен через `KIWI_NEVERTIME` (`MAXLONGLONG`)

Иллюстрация (данные прямиком из AD):

- Golden: ![Golden LogonCount + PasswordLastSet](SlidesAndDocs/Pic/LogonCount_and_PwdLastSet_BAD.png)
- Legit: ![Real LogonCount + PasswordLastSet](SlidesAndDocs/Pic/EffectiveName_and_time_is_OK.png)

Почему это происходит:

- [kuhl_m_kerberos_pac.c#L154](https://github.com/gentilkiwi/mimikatz/blob/306bc6b43099c7b698f2898401fddbded6a630c8/mimikatz/modules/kerberos/kuhl_m_kerberos_pac.c#L154)
- [globals.h#L97 (KIWI_NEVERTIME)](https://github.com/gentilkiwi/mimikatz/blob/306bc6b43099c7b698f2898401fddbded6a630c8/inc/globals.h#L97)
- [MS-PAC / PasswordLastSet](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/69e86ccc-85e3-41b9-b514-7d969cd0ed73)

Примечание: по спецификации для случая "password never set" у `PasswordLastSet` ожидается
нулевое FILETIME-значение. Поэтому `MAXLONGLONG` является полезным артефактом для корреляции.

### Признак 6: `crealm` в lowercase (эвристика)

Если в поддельном билете `crealm` копируется напрямую из CLI-параметра и остаётся lowercase,
а в легитимной инфраструктуре вы обычно видите uppercase-канон, это полезная эвристика.

Важно: использовать только как дополнительный сигнал, не как самостоятельный verdict.
Полагаться лучше на PAC/token-сигналы выше.

---

## Требования

- Runtime: domain-joined Windows x64 с .NET Framework 4.8; первая lab target —
  Windows Server 2019.
- Служба устанавливается администратором и работает как LocalSystem. Только
  интерактивный CLI при необходимости выполняет legacy SYSTEM impersonation.
- Build: Visual Studio 2022 с MSBuild, Desktop C++/Windows SDK, NuGet CLI,
  .NET SDK 8+ для WiX SDK restore и WiX Toolset 7.0.0.
- Для WiX 7 требуется явное принятие OSMF EULA `wix7`.

## Сборка

```powershell
.\tools\Build-Release.ps1 -ProductVersion 1.0.0
```

Скрипт восстанавливает classic `packages.config` и WiX SDK, собирает
`Release|x64`, запускает tests, ICE validation и MSI table assertions.
Результат: `FindGT.Setup\bin\x64\Release\FindGT-1.0.0-x64.msi`.

## Использование

```console
FindGT [OPTIONS] [COMMAND]

OPTIONS:
  -v, --verbose   Показать все группы каждой сессии, а не только расхождения
      --html      Сохранить отчёт как HTML‑файл в текущую папку
  -h, --help      Показать справку

COMMANDS:
  test-s4u <upn> [realm]                   Членство через S4U2Self для одного пользователя
  test-securechannel <nthash-file> [dc]    Установить и проверить Netlogon secure channel
  test-securechannel-raw <file> [dc]       Перебор деривации машинного секрета
  test-crypto                              Самотест MD4 / AES-CFB8
```

По умолчанию (без команды) = скан всех Kerberos‑сессий и вывод **только расхождений**.

Silent MSI install без немедленного запуска службы:

```powershell
msiexec.exe /i .\FindGT-1.0.0-x64.msi /qn START_SERVICE=0 `
  SECURITY_SINK_MODE=SuspiciousOnly ENABLE_JSON_SINK=0 `
  /L*v .\FindGT-install.log
```

Interactive MSI показывает options для start, existing sessions, Security,
JSON, PowerfulOnly и сохранения config. Все options также доступны как public
MSI properties; см. [инструкцию](docs/installation/msi.md).

## Вывод

Одна таблица Spectre.Console на сессию: **SID | Имя | Комментарий**, с цветовой кодировкой
(красный = подозрительно, жёлтый = нет в токене, зелёный = совпадение, видно при `--verbose`).
`--html` экспортирует самодостаточный HTML‑документ в UTF‑8 в текущую папку.

Служба пишет terminal result каждой оценённой сессии в `FindGT/Operational`.
Events содержат `AnalysisId`, full LUID, trigger metadata, verdict, rule IDs,
reference status и bounded evidence. Security event содержит только summary и
связывается с Operational через `AnalysisId`.

## Реализовано

- [x] Сохранённый CLI и общий `FindGT.Core` на .NET Framework 4.8 x64.
- [x] Full 64-bit LUID, SafeHandle ownership и boot-aware dedupe.
- [x] Авторитетное членство через S4U2Self (`KERB_S4U_LOGON`).
- [x] LDAP fallback без success-shaped partial results.
- [x] Typed verdict и FGT001–FGT010 rule engine.
- [x] Event 4624 named-field parser/watcher, bounded queue, bookmark и reconciliation.
- [x] LocalSystem Windows service с retry, health states и bounded shutdown.
- [x] Manifest-based Operational, Authz Security и optional JSONL sinks.
- [x] WiX 7 x64 MSI, interactive/silent options, ACL/Authz/service recovery actions.
- [x] Unit tests, reproducible build scripts и Windows 2022 CI/release workflows.
- [x] NRPC и `LsaSecretExtractor` сохранены как отдельные research diagnostics.

## План / TODO

- [ ] Подтвердить MSI install/repair/upgrade/uninstall и event registration в
      disposable Windows environment.
- [ ] Выполнить end-to-end lab test: legitimate admin, существующая forged session
      через startup reconciliation и новый Golden Ticket вход с настоящим 4624.
- [ ] Зафиксировать evidence для PowerfulOnly и DC unavailable → `Unknown`.
- [ ] Включить production code signing после предоставления сертификата.
- [ ] **Опция B** — полностью автономный raw‑Kerberos S4U2Self + U2U (независимо от локального
      LSASS). Подробный план: [SlidesAndDocs/OptionB-RawKerberos-S4U2Self.md](SlidesAndDocs/OptionB-RawKerberos-S4U2Self.md).
- [ ] Optional / policy-driven response including logoff для подозрительных сессий.
- [ ] Расширить multi-DC/cross-forest validation и SIEM mappings.

> Примечание: NRPC `NetrLogonSamLogonEx` рассматривался как источник членства, но **не может**
> вернуть группы произвольного пользователя без его учётных данных (S4U на уровне Netlogon нет),
> поэтому механизмом членства выбран S4U2Self (Kerberos).

## Благодарности и лицензия

Частично основано на [GhostPack/Koh](https://github.com/GhostPack/Koh). Свободно и
открыто, предоставляется **«как есть», без гарантий**. Только для **авторизованного**
тестирования безопасности.
