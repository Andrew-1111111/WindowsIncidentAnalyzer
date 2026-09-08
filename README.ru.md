# Windows Incident Analyzer

Консольное приложение для **защитного** анализа журналов Windows: сбор событий, поиск, timeline, детектирование, правила Sigma, сопоставление IOC, сканирование CVE (CISA KEV), обогащение MITRE ATT&CK, корреляция и экспорт.

Инструмент предназначен для incident response, DFIR и threat hunting на системах, которые вы уполномочены расследовать. Он **не** эксплуатирует уязвимости, не обходит средства защиты и не выполняет удалённые атаки.

**English version:** [README.md](README.md)

## Возможности

- Сбор из каналов журнала событий Windows (набор по умолчанию, **все доступные** каналы, один канал или импорт EVTX)
- Хранение в SQLite через **EF Core**: нормализованные поля событий, properties, findings, IOC и каталог CVE
- **19 движков детектирования**: поведенческие правила, сигнатуры угроз и **Sigma** (набор правил Hayabusa)
- Структурированные findings (`FindingContext`) с метаданными события, деталями Sigma и тегами MITRE (обогащение из локальной базы ATT&CK)
- Проверка соответствия типа события и серьёзности CRIT/HIGH фактическому событию
- IOC из JSON и автообновление из публичных defensive-фидов
- Автозагрузка правил Sigma (Hayabusa), MITRE ATT&CK и CISA KEV при старте (с кэшем)
- Корреляция цепочек аутентификации, учётных записей, persistence и PowerShell
- Экспорт в **JSON**, **HTML** и **Excel (.xlsx)** с полным набором данных расследования
- Интерактивная консоль `wia>` при запуске без аргументов
- Поддержка русских и английских имён журналов (`Security` / `Безопасность`)

## Требования

- Windows (API журнала событий)
- [.NET 9 SDK](https://dotnet.microsoft.com/download)
- **Права администратора** для журнала Security и Sysmon (EVTX, Application, System, PowerShell, поиск, analyze, IOC, CVE и экспорт работают без повышения прав)

## Сборка

```bash
dotnet build
dotnet test
```

В тестовом наборе сейчас **187** тестов. Исполняемый файл: `wia.exe`. Рабочие данные и логи — в каталоге `data/` рядом с `wia.exe`.

### Локальная публикация

| Вариант | Команда | Примечание |
| --- | --- | --- |
| **AnyCPU** (framework-dependent) | `dotnet publish -c Release` | Нужен [.NET 9 runtime](https://dotnet.microsoft.com/download) |
| **x64** (framework-dependent) | `dotnet publish -c Release -r win-x64 --self-contained false` | Нужен .NET 9 runtime |
| **x64 self-contained** | `dotnet publish -c Release -r win-x64 --self-contained true` | Runtime входит в сборку |

### GitHub Actions

Каждый push и pull request в `main` / `master` запускает [.github/workflows/build.yml](.github/workflows/build.yml) на `windows-latest`: тесты и три ZIP-артефакта (`wia-anycpu-fdd`, `wia-win-x64-fdd`, `wia-win-x64-self-contained`). Ручной запуск: **Actions → Build → Run workflow**.

### GitHub Releases

Тег `v*` (например `v1.1.0`) создаёт Release со всеми тремя ZIP:

```bash
git tag v1.1.0
git push origin v1.1.0
```

Джоб Release запускается только при push тега (обычный push в `master` релиз не создаёт). Рекомендуемый пакет: `wia-win-x64-self-contained.zip`.

## Запуск

```bash
# Интерактивный режим
wia

# Или отдельные команды
wia collect --hours 24
wia analyze
wia export --format html --output data/report.html
```

Пропустить онлайн-обновление threat intelligence при старте:

```bash
wia --skip-bootstrap analyze
```

При старте (кроме help/version) выводится краткая **сводка по БД расследования** (число событий, диапазон времени, findings, корреляции, инциденты, IOC/CVE). Скачивание threat intel по-прежнему отключается через `--skip-bootstrap`.

## Старт и threat intelligence

При запуске приложение может автоматически:

1. Скачать и импортировать **IOC-фиды** (по умолчанию: каждые 6 часов)
2. Скачать правила **Hayabusa** (Sigma/native) в `data/sigma-rules/` (по умолчанию: каждые 24 часа)
3. Скачать бандл **MITRE ATT&CK** в `data/mitre/` (по умолчанию: каждые 7 дней)
4. Скачать каталог **CISA KEV** в SQLite (по умолчанию: каждые 7 дней)

Настройки в `Configuration/appsettings.json`:

```json
"Startup": {
  "AutoUpdateIocFeeds": true,
  "AutoUpdateSigmaRules": true,
  "AutoUpdateMitreAttack": true,
  "AutoUpdateCveDatabase": true,
  "IocRefreshHours": 6,
  "SigmaRefreshHours": 24,
  "MitreRefreshHours": 168,
  "CveRefreshHours": 168
}
```

При использовании кэша выводятся количества IOC, Sigma, MITRE и CVE и время следующего обновления.

## Команды

| Команда | Назначение |
| --- | --- |
| `collect` | Сбор из журналов или EVTX в SQLite |
| `search` | Поиск по собранным событиям |
| `timeline` | Хронология, опциональный экспорт |
| `analyze` | Детекторы + обогащение MITRE + IOC/CVE + корреляция |
| `ioc import` / `ioc update` / `ioc scan` | Импорт, обновление и поиск IOC |
| `sigma load` / `sigma update` / `sigma list` / `sigma stats` | Управление правилами Sigma |
| `mitre load` / `mitre update` / `mitre lookup` / `mitre stats` | База MITRE ATT&CK |
| `cve load` / `cve update` / `cve lookup` / `cve scan` / `cve stats` | Каталог CVE (CISA KEV) |
| `export` | Отчёт JSON / HTML / Excel (те же фильтры, что у search) |
| `stats` | Статистика по событиям и findings |

Общие фильтры: `--hours`, `--from`, `--to`, `--date`, `--user`, `--ip`, `--process`, `--event-id`, `--keyword`, `--limit`.

### Сбор

```bash
wia collect --log Security
wia collect --log all --hours 24
wia collect --log Sysmon --hours 24
wia collect --date 2026-08-29
wia collect --from "2026-08-01 00:00:00" --to "2026-08-02 00:00:00"
wia collect --event-id 4624,4625,4688
wia collect --evtx "C:\Evidence\Security.evtx" --batch-size 500 --limit 100000
```

Без `--log` набор каналов зависит от `CollectAllLogs` в `appsettings.json` (`false` = Security, System, Application, PowerShell, Sysmon; `true` = все доступные каналы). `--log all` — все каналы явно; `--log Security` и т.д. — один канал. Недоступные каналы пропускаются.

По умолчанию `collect` читает **все события за всё время** без лимита. Ограничить период: `--hours`, `--from` / `--to`, `--date`; число событий: `--limit`. Параллелизм задаётся корневым `MaxDegreeOfParallelism` (`0` = без лимита, `1` = последовательно, `N` = потолок).

### Поиск

```bash
wia search --event-id 4625 --user admin --hours 24 --limit 1000
wia search --keyword "mimikatz"
```

Поиск охватывает нормализованные поля, Raw XML и properties.

### Timeline

```bash
wia timeline --hours 24
wia timeline --user admin --export timeline.json
```

### Analyze

Запускает все включённые детекторы, обогащение MITRE, IOC/CVE и корреляцию. Findings выводятся **списком**:

```text
CRIT 2026-08-29 15:03:14 evt 4104 CredentialAccess
      Kerberos ticket theft or forging
      type=ps_script | host=WIN-DEVLAB | proc=powershell.exe
      Command or script contains Kerberos ticket extraction/forging indicators.
_________________________________________
HIGH 2026-03-18 13:37:10 evt 104 LogClearing
      Windows event channel was cleared
      type=log_clearing | host=WIN-DEVLAB | user=admin
```

При несовпадении категории правила или серьёзности CRIT/HIGH с фактическим событием выводится предупреждение; завышенная серьёзность может быть понижена автоматически.

```bash
wia analyze
wia analyze --hours 24 --limit 100000
```

### IOC

```bash
wia ioc import samples/indicators.json
wia ioc update --save samples/indicators.json
wia ioc scan
wia ioc scan --hours 24
```

`ioc update` скачивает публичные фиды параллельно (таймаут на фид, пакетная запись в SQLite). Типы: `ip`, `domain`, `hash`, `filename`, `url`, `user`.

### Sigma

```bash
wia sigma update
wia sigma load data/sigma-rules
wia sigma list --limit 20
wia sigma stats
```

Правила загружаются из архива [Hayabusa rules](https://github.com/Yamato-Security/hayabusa-rules) (Sigma + native YAML). Применяются в `analyze` при `SigmaRules.Enabled: true` в `DetectionRules.json`. Совпадения заполняют `FindingContext` (поля/значения, condition, MITRE, Sigma ID).

### MITRE ATT&CK

```bash
wia mitre update
wia mitre load data/mitre/enterprise-attack.json
wia mitre lookup T1033
wia mitre lookup attack.discovery
wia mitre stats
```

Источник: [mitre/cti](https://github.com/mitre/cti) `enterprise-attack.json` (STIX 2.1). При `analyze` и `export` теги MITRE из Sigma обогащаются именами техник/тактик и URL ATT&CK.

### CVE (CISA KEV)

```bash
wia cve update
wia cve load data/cve/known_exploited_vulnerabilities.json
wia cve lookup CVE-2024-1234
wia cve scan
wia cve stats
```

Источник: [каталог CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog). `cve scan` и `analyze` ищут CVE ID из каталога в собранных событиях (командные строки, script blocks, Raw XML, properties).

### Экспорт

```bash
wia export --format json --output data/report.json
wia export --format html --output data/report.html
wia export --format csv --output data/investigation.csv
wia export --hours 24 --user admin --format html
wia stats
```

#### JSON

Один файл со всеми данными: `filter`, `statistics`, `findings` (с полным `context`), `correlations`, `iocMatches`, `cveMatches`, `timeline`, `events`. Кириллица в UTF-8 без лишнего escape.

#### HTML

Автономный тёмный отчёт:

- Карточки серьёзности; Critical/High и все findings (**59** колонок, как в Excel)
- IOC, CVE, корреляции, timeline
- Связанные события (**35** колонок): процесс, сеть, script block, properties JSON, Raw XML
- Длинные поля полностью доступны в collapsible-блоках
- Статистика (топ Event ID, пользователи, процессы, IP, события по часам)

#### CSV (`--format csv`)

Создаёт **файлы Excel `.xlsx`** с жирными заголовками и автофильтром:

| Файл | Содержимое |
| --- | --- |
| `*-findings.xlsx` | 59 колонок: серьёзность, ID, метаданные правила, тип события, флаги валидации, процесс/сеть/файл, Sigma/MITRE, raw evidence |
| `*-timeline.xlsx` | Timeline + ID события |
| `*-iocs.xlsx` | Совпадения IOC + ID события |
| `*-cves.xlsx` | Совпадения CVE (CISA KEV) + ID события |
| `*-correlations.xlsx` | Корреляции + связанные ID событий |
| `*-events.xlsx` | Полные нормализованные события (35 колонок) + properties JSON |
| `*-statistics.xlsx` | Сводка, фильтр, разбивки статистики |

## Детектирование

### Поведенческие детекторы

| Детектор | Фокус |
| --- | --- |
| `FailedLogon` | Кластеры неудачных входов 4625 |
| `SuccessfulLogon` | Удалённые и explicit-credential входы |
| `BruteForce` | Всплески неудач, password spraying, успешный brute force |
| `NewUser` | Создание учёток и добавление в привилегированные группы |
| `PrivilegeChange` | Изменения членства в чувствительных группах |
| `ProcessCreation` | Подозрительные пути, parent/child, длинные командные строки |
| `SuspiciousPowerShell` | Encoded-команды, загрузки, обфускация (только текст) |
| `ScheduledTask` | Подозрительные задачи |
| `ServiceInstallation` | Новые службы |
| `RdpActivity` | Входы RDP (тип 10) |
| `LogClearing` | Очистка журнала (104 / 1102) |

### Сигнатурные детекторы

`CredentialAccess`, `DefenseEvasion`, `PersistenceAndLolbin`, `LateralMovementAndDiscovery`, `SecurityPolicyChange`, `MalwareBehavior`, `KerberosAndDirectoryAttack` — сотни сигнатур по командным строкам и содержимому событий.

### Sigma

Тысячи правил Hayabusa/Sigma с сопоставлением logsource, модификаторами полей и условиями. Findings содержат `MatchedFields`, `MatchedValues`, `Condition`, `MitreTactic` и др.

### Корреляция

Примеры цепочек:

1. `4625 × N → 4624 → 4672` — возможный компромисс привилегированной учётки
2. `4720 → 4728/4732 → 4624` — подозрительное создание учётки
3. `4698 → 4688` — возможный persistence
4. PowerShell `4104` → Sysmon `1` → Sysmon `3` — script / process / network

### Модель finding

- Поля finding: `RuleName`, `Title`, `Severity`, `TimeUtc`, …
- **`FindingContext`**: `EventId`, `Provider`, `Channel`, процесс, сеть, файлы, Sigma, MITRE, `RawXml`, `RawEvent`
- **`EventType`** — тип события, выведенный из EventId и провайдера
- **`CategoryMatchesEvent`** / **`SeverityMatchesEvent`** — результаты валидации

## Конфигурация

| Файл | Назначение |
| --- | --- |
| `Configuration/appsettings.json` | Путь к БД, `MaxDegreeOfParallelism`, сбор, автообновление IOC/Sigma/MITRE/CVE |
| `Configuration/DetectionRules.json` | Включение детекторов, пороги, настройки Sigma |

Отключить детектор:

```json
{
  "BruteForce": { "Enabled": false },
  "SigmaRules": {
    "Enabled": true,
    "RulesPath": "sigma-rules",
    "IncludeExperimental": false
  }
}
```

База по умолчанию: `data/investigation.db`. Лог: `data/wia.log`.

## Архитектура

```text
Program.cs  →  ApplicationBootstrap (сводка БД + IOC/Sigma/MITRE/CVE)
           →  System.CommandLine
                    │
     collect / search / timeline / analyze / ioc / sigma / mitre / cve / export / stats
                    │
         Services (сбор, детект, корреляция, IOC/CVE, MITRE, экспорт)
                    │
         Repositories  →  EF Core / SQLite (Persistence/)
                    │
         EventXmlParser + EventFieldMapper  →  WindowsEvent
                    │
         Detectors (behavioral + signatures + SigmaRuleEngine)
```

## PowerShell

Текст script block сохраняется и хешируется. Base64 может декодироваться **только для просмотра аналитиком**. Приложение **никогда** не выполняет PowerShell.

## Права и ошибки

| Ситуация | Поведение |
| --- | --- |
| Без прав администратора | Ограниченный режим: Security/Sysmon недоступны; остальное работает |
| Доступно повышение UAC | Перезапуск от администратора (если не указан `--limited`) |
| Журнал Sysmon/PowerShell отсутствует | Канал пропускается |
| Повреждённая запись EVTX | Запись пропускается |
| Некорректный IOC JSON | Импорт прерывается с понятным сообщением |
| Ошибка SQLite | Логируется, ненулевой код выхода |

## Структура проекта

| Папка | Роль |
| --- | --- |
| `Commands/` | CLI-команды |
| `Services/` | Сбор, анализ, IOC/CVE, MITRE, экспорт, статистика |
| `Detectors/` | Встроенные и сигнатурные детекторы |
| `Sigma/` | Парсер YAML, движок, каталог logsource |
| `Mitre/` | Парсеры ATT&CK STIX и CISA KEV |
| `Models/` | События, findings, корреляции, фильтры |
| `Persistence/` | EF Core `DbContext`, сущности, мапперы |
| `Repositories/` | Доступ к данным через EF Core |
| `Infrastructure/` | Bootstrap, схема БД, пути, elevation, HTTP resilience |
| `Exporters/` | JSON, HTML, Excel |
| `Configuration/` | `appsettings.json`, `DetectionRules.json` |
| `WindowsIncidentAnalyzer.Tests/` | Unit- и интеграционные тесты |
