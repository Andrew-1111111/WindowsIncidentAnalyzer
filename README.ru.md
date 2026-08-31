# Windows Incident Analyzer

Консольное приложение для **защитного** анализа журналов Windows: сбор событий, поиск, timeline, детектирование, правила Sigma, сопоставление IOC, корреляция и экспорт.

Инструмент предназначен для incident response, DFIR и threat hunting на системах, которые вы уполномочены расследовать. Он **не** эксплуатирует уязвимости, не обходит средства защиты и не выполняет удалённые атаки.

## Возможности

- Сбор из Security, System, Application, PowerShell, Sysmon или импорт EVTX (только чтение)
- Хранение в SQLite с нормализованными полями и полным набором properties
- **19 движков детектирования**: поведенческие правила, сигнатуры угроз и **Sigma** (SigmaHQ)
- Структурированные findings (`FindingContext`) с метаданными события, деталями Sigma и тегами MITRE
- Проверка соответствия типа события и серьёзности CRIT/HIGH фактическому событию
- IOC из JSON и автообновление из публичных defensive-фидов
- Автозагрузка правил Sigma с SigmaHQ при старте (с кэшем)
- Корреляция цепочек аутентификации, учётных записей, persistence и PowerShell
- Экспорт в **JSON**, **HTML** и **Excel (.xlsx)** с полным набором данных расследования
- Интерактивная консоль `wia>` при запуске без аргументов
- Поддержка русских и английских имён журналов (`Security` / `Безопасность`)

## Требования

- Windows
- SDK .NET 9
- **Права администратора** для журнала Security и Sysmon (EVTX, Application, System, PowerShell, поиск, analyze, IOC и экспорт работают без повышения прав)

## Сборка и запуск

```bash
dotnet build
dotnet test

# Интерактивный режим
wia

# Или отдельные команды
wia collect --hours 24
wia analyze
wia export --format html --output data/report.html
```

Исполняемый файл: `wia.exe`. Данные и логи — в каталоге `data/` рядом с `wia.exe`.

Пропустить онлайн-обновление IOC/Sigma при старте:

```bash
wia --skip-bootstrap analyze
```

## Старт и threat intelligence

При запуске приложение может автоматически:

1. Скачать и импортировать **IOC-фиды** (по умолчанию: каждые 6 часов)
2. Скачать правила **SigmaHQ** в `data/sigma-rules/` (по умолчанию: каждые 24 часа)

Настройки в `Configuration/appsettings.json`:

```json
"Startup": {
  "AutoUpdateIocFeeds": true,
  "AutoUpdateSigmaRules": true,
  "IocRefreshHours": 6,
  "SigmaRefreshHours": 24
}
```

При использовании кэша выводится количество IOC и Sigma-правил и время следующего обновления. Правила Sigma загружаются с диска в память при каждом старте.

## Команды

| Команда | Назначение |
| --- | --- |
| `collect` | Сбор из журналов или EVTX в SQLite |
| `search` | Поиск по собранным событиям |
| `timeline` | Хронология, опциональный экспорт |
| `analyze` | Детекторы + IOC + корреляция |
| `ioc import` / `ioc update` / `ioc scan` | Импорт, обновление и поиск IOC |
| `sigma load` / `sigma update` / `sigma list` / `sigma stats` | Управление правилами Sigma |
| `export` | Отчёт JSON / HTML / Excel |
| `stats` | Статистика по событиям и findings |

Общие фильтры времени: `--hours`, `--from`, `--to`, `--date`, `--user`, `--ip`, `--process`, `--event-id`, `--keyword`, `--limit`.

### Сбор

```bash
wia collect --log Security --hours 24
wia collect --date 2026-08-29
wia collect --evtx "C:\Evidence\Security.evtx"
```

Без `--log` собираются Security, PowerShell Operational и Sysmon (отсутствующие журналы пропускаются).

### Analyze

Запускает все включённые детекторы, IOC и корреляцию. Findings выводятся **списком**:

```text
CRIT 2026-08-29 15:03:14 evt 4104 CredentialAccess
      Kerberos ticket theft or forging
      type=ps_script | host=WIN-DEVLAB | proc=powershell.exe
      Command or script contains Kerberos ticket extraction/forging indicators.
_________________________________________
```

При несовпадении категории правила или серьёзности CRIT/HIGH с фактическим событием выводится предупреждение; завышенная серьёзность может быть понижена автоматически.

### IOC

```bash
wia ioc import samples/indicators.json
wia ioc update --save samples/indicators.json
wia ioc scan --hours 24
```

`ioc update` скачивает публичные фиды параллельно (таймаут на фид, пакетная запись в SQLite).

### Sigma

```bash
wia sigma update
wia sigma load data/sigma-rules
wia sigma list --limit 20
wia sigma stats
```

Правила Sigma применяются в `analyze` при `SigmaRules.Enabled: true` в `DetectionRules.json`.

### Экспорт

```bash
wia export --format json --output data/report.json
wia export --format html --output data/report.html
wia export --format csv --output data/investigation.csv
```

#### JSON

Один файл со всеми данными расследования: `filter`, `statistics`, `findings` (с полным `context`), `correlations`, `iocMatches`, `timeline`, `events`. Кириллица в UTF-8 без escape-последовательностей.

#### HTML

Автономный тёмный отчёт: фильтр, findings, IOC, корреляции, timeline, связанные события, полная статистика.

#### CSV (`--format csv`)

Создаёт **файлы Excel `.xlsx`** с жирными заголовками и автофильтром:

| Файл | Содержимое |
| --- | --- |
| `*-findings.xlsx` | 56 колонок: серьёзность, ID, метаданные правила, тип события, флаги валидации, процесс/сеть/файл, Sigma/MITRE, raw evidence |
| `*-timeline.xlsx` | Timeline + ID события |
| `*-iocs.xlsx` | Совпадения IOC + ID события |
| `*-correlations.xlsx` | Корреляции + связанные ID событий |
| `*-events.xlsx` | Полные нормализованные события (35 колонок) + properties JSON |
| `*-statistics.xlsx` | Сводка, фильтр, разбивки статистики |

## Детектирование

### Поведенческие детекторы

Неудачные и успешные входы, brute force / password spraying, создание пользователей, изменение привилегий, подозрительные процессы и PowerShell, задачи по расписанию, службы, RDP, очистка журналов.

### Сигнатурные детекторы

`CredentialAccess`, `DefenseEvasion`, `PersistenceAndLolbin`, `LateralMovementAndDiscovery`, `SecurityPolicyChange`, `MalwareBehavior`, `KerberosAndDirectoryAttack` — сотни IOC-подобных сигнатур по командным строкам и содержимому событий.

### Sigma

Тысячи правил SigmaHQ с сопоставлением logsource, модификаторами полей и условиями. Findings содержат `MatchedFields`, `MatchedValues`, `Condition`, `MitreTactic` и др.

### Модель finding

- Поля finding: `RuleName`, `Title`, `Severity`, `TimeUtc`, …
- **`FindingContext`**: `EventId`, `Provider`, `Channel`, процесс, сеть, файлы, Sigma, MITRE, `RawXml`, `RawEvent`
- **`EventType`** — тип события, выведенный из EventId и провайдера
- **`CategoryMatchesEvent`** / **`SeverityMatchesEvent`** — результаты валидации

## Конфигурация

| Файл | Назначение |
| --- | --- |
| `Configuration/appsettings.json` | Путь к БД, параллелизм, автообновление IOC/Sigma |
| `Configuration/DetectionRules.json` | Включение детекторов, пороги, настройки Sigma |

База по умолчанию: `data/investigation.db`. Лог: `data/wia.log`.

## PowerShell

Текст script block сохраняется и хешируется. Base64 может декодироваться **только для просмотра аналитиком**. Приложение **никогда** не выполняет PowerShell.

## Права и ошибки

| Ситуация | Поведение |
| --- | --- |
| Без прав администратора | Ограниченный режим: Security/Sysmon недоступны; остальное работает |
| Доступно повышение UAC | Перезапуск от администратора (если не указан `--limited`) |
| Журнал Sysmon/PowerShell отсутствует | Канал пропускается |
| Повреждённая запись EVTX | Запись пропускается |
| Ошибка SQLite | Логируется, ненулевой код выхода |

## Структура проекта

`Commands/`, `Services/`, `Detectors/`, `Sigma/`, `Models/`, `Repositories/`, `Infrastructure/`, `Exporters/`, `Configuration/`, `WindowsIncidentAnalyzer.Tests/`.

Полная документация на английском: [README.md](README.md).
