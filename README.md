# Windows Incident Analyzer

Console application for **defensive** Windows Event Log analysis: collection, search, timeline construction, detection, Sigma rules, IOC matching, correlation, and export.

The tool is intended for incident response, DFIR, and threat hunting on systems you are authorized to investigate. It does **not** exploit vulnerabilities, bypass security controls, or perform remote attacks.

## Features

- Live collection from Security, System, Application, PowerShell, and Sysmon channels, or read-only EVTX import
- SQLite-backed storage with normalized event fields and full property bags
- **19 detection engines**: behavioral rules, known-threat signatures, and **Sigma** (SigmaHQ)
- Structured findings (`FindingContext`) with event metadata, Sigma match details, and MITRE tags
- Event-type and severity validation (category / CRIT–HIGH alignment with the source event)
- IOC import from JSON and automatic refresh from public defensive feeds
- Automatic Sigma rule download from SigmaHQ on startup (cached)
- Correlation chains across authentication, account creation, persistence, and PowerShell activity
- Export to **JSON**, **HTML**, and **Excel (.xlsx)** with the full investigation payload
- Interactive `wia>` console when launched without arguments
- Russian and English Windows log names (`Security` / `Безопасность`, etc.)

## Requirements

- Windows (Event Log APIs)
- [.NET 9 SDK](https://dotnet.microsoft.com/download)
- **Administrator** privileges for the **Security** log and Sysmon (EVTX, Application, System, PowerShell, search, analyze, IOC, and export work without elevation)

## Build

```bash
dotnet build
dotnet test
```

The compiled executable is named `wia.exe`. Data and logs are stored next to the executable under `data/`.

## Run

```bash
# Interactive shell (wia> prompt)
wia

# Or single commands
wia collect --hours 24
wia analyze
wia export --format html --output data/report.html
```

Skip online IOC/Sigma refresh on startup (offline / fast start):

```bash
wia --skip-bootstrap analyze
```

## Startup and threat intelligence

On launch, the application can automatically:

1. Download and import public **IOC feeds** (default: every 6 hours)
2. Download **SigmaHQ** Windows rules into `data/sigma-rules/` (default: every 24 hours)

Settings in `Configuration/appsettings.json`:

```json
"Startup": {
  "AutoUpdateIocFeeds": true,
  "AutoUpdateSigmaRules": true,
  "IocRefreshHours": 6,
  "SigmaRefreshHours": 24
}
```

When feeds are cached, startup shows IOC and Sigma counts and the next refresh time. Sigma rules are loaded from disk into memory on every start.

## Commands

| Command | Purpose |
| --- | --- |
| `collect` | Read live channels or a read-only EVTX file into SQLite |
| `search` | Query collected events |
| `timeline` | Chronological view, optional export |
| `analyze` | Detection rules + IOC scan + correlation |
| `ioc import` / `ioc update` / `ioc scan` | Load, refresh, and match indicators |
| `sigma load` / `sigma update` / `sigma list` / `sigma stats` | Manage Sigma rules |
| `export` | JSON / HTML / Excel report |
| `stats` | Event ID, user, process, IP, and finding counts |

Global time filters (most commands): `--hours`, `--from`, `--to`, `--date`, `--user`, `--ip`, `--process`, `--event-id`, `--keyword`, `--limit`.

### Collect

```bash
wia collect --log Security
wia collect --log Sysmon --hours 24
wia collect --date 2026-08-29
wia collect --from "2026-08-01 00:00:00" --to "2026-08-02 00:00:00"
wia collect --event-id 4624,4625,4688
wia collect --evtx "C:\Evidence\Security.evtx" --batch-size 500 --limit 100000
```

If `--log` is omitted, the collector tries **Security**, **Microsoft-Windows-PowerShell/Operational**, and **Microsoft-Windows-Sysmon/Operational**. Missing channels are skipped.

### Search

```bash
wia search --event-id 4625 --user admin --hours 24 --limit 1000
wia search --keyword "mimikatz"
```

Search covers normalized fields, Raw XML, and event properties.

### Timeline

```bash
wia timeline --hours 24
wia timeline --user admin --export timeline.json
```

### Analyze

Runs all enabled detectors, IOC matching, and correlation. Findings are stored in SQLite and printed in a **list format** (not a wide table):

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

Warnings are shown when a rule category or CRIT/HIGH severity does not match the actual event.

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

`ioc update` downloads public defensive feeds in parallel (per-feed timeout, batch SQLite import). Supported types: `ip`, `domain`, `hash`, `filename`, `url`, `user`.

Bundled `samples/indicators.json` can be refreshed with `ioc update`.

### Sigma

```bash
wia sigma update
wia sigma load data/sigma-rules
wia sigma list --limit 20
wia sigma stats
```

Sigma rules are evaluated during `analyze` when `SigmaRules.Enabled` is true in `DetectionRules.json`. Matches populate `FindingContext` (matched fields/values, condition, MITRE tags, Sigma ID).

### Export

```bash
wia export --format json --output data/report.json
wia export --format html --output data/report.html
wia export --format csv --output data/investigation.csv
wia stats
```

#### JSON

Single file with the full investigation payload:

- `filter` — query parameters used for export
- `statistics` — counts by severity, event ID, user, process, IP, hour
- `findings` — with complete `context` (event fields, Sigma, MITRE, raw event JSON, raw XML)
- `correlations`, `iocMatches`, `timeline`
- `events` — all normalized Windows events referenced by the above

UTF-8 with readable Cyrillic (`UnsafeRelaxedJsonEscaping`).

#### HTML

Self-contained dark-theme report (no CDN):

- Investigation filter metadata
- Findings (critical/high and all), IOC matches, correlations, timeline
- Related events table with process, network, script-block, and property details
- Full statistics (top event IDs, users, processes, IPs, events by hour)

#### CSV (`--format csv`)

Writes **Excel `.xlsx`** files with bold centered headers and auto-filter:

| File | Contents |
| --- | --- |
| `*-findings.xlsx` | 56 columns: severity, IDs, rule metadata, event type, validation flags, process/network/file fields, Sigma/MITRE, raw evidence |
| `*-timeline.xlsx` | Timeline items + event row ID |
| `*-iocs.xlsx` | IOC matches + event row ID |
| `*-correlations.xlsx` | Correlation chains + related event IDs |
| `*-events.xlsx` | Full normalized events (35 columns) + properties JSON |
| `*-statistics.xlsx` | Summary, filter, and all statistic breakdowns |

## Detection

### Built-in behavioral detectors

| Detector | Focus |
| --- | --- |
| `FailedLogon` | Clustered 4625 failures |
| `SuccessfulLogon` | Remote and explicit-credential logons |
| `BruteForce` | Failed logon bursts, password spraying, successful brute force |
| `NewUser` | Account creation and privileged group adds |
| `PrivilegeChange` | Sensitive group membership changes |
| `ProcessCreation` | Suspicious paths, parent/child pairs, long command lines |
| `SuspiciousPowerShell` | Encoded commands, downloads, obfuscation (textual only) |
| `ScheduledTask` | Suspicious task creation |
| `ServiceInstallation` | New services |
| `RdpActivity` | Remote Desktop logons (type 10) |
| `LogClearing` | Event log cleared (104 / 1102) |

### Signature-based detectors (`KnownThreatSignatures`)

| Detector | Focus |
| --- | --- |
| `CredentialAccess` | LSASS access, credential dumping, SAM/NTDS, Kerberos attacks |
| `DefenseEvasion` | Log clearing commands, Defender tampering, shadow copy deletion |
| `PersistenceAndLolbin` | WMI persistence, Run keys, LOLBins (regsvr32, mshta, certutil, …) |
| `LateralMovementAndDiscovery` | PsExec, remote execution, discovery tools |
| `SecurityPolicyChange` | Audit policy, firewall, Kerberos/domain policy |
| `MalwareBehavior` | Process tampering, unsigned drivers, ransomware indicators |
| `KerberosAndDirectoryAttack` | DCSync, Kerberoasting, AS-REP roasting |

### Sigma (`SigmaRules`)

Thousands of SigmaHQ rules with logsource matching, field modifiers, and condition evaluation. Findings use `RuleName = SigmaRules` and detailed `FindingContext`.

### Correlation

Multi-event chains, for example:

1. `4625 × N → 4624 → 4672` — potential compromised privileged account
2. `4720 → 4728/4732 → 4624` — suspicious account creation
3. `4698 → 4688` — potential persistence
4. PowerShell `4104` → Sysmon `1` → Sysmon `3` — script / process / network chain

### Finding model

Each finding includes:

- Legacy fields: `RuleName`, `Title`, `Severity`, `TimeUtc`, `ComputerName`, `User`, …
- **`FindingContext`**: `EventId`, `Provider`, `Channel`, process/network/file fields, `SigmaId`, `MatchedFields`, `MitreTactic`, `RawXml`, `RawEvent` (JSON), …
- **`EventType`** — inferred Sigma-style category from the actual event
- **`CategoryMatchesEvent`** / **`SeverityMatchesEvent`** — validation flags; severity may be capped when mismatched

## Configuration

| File | Purpose |
| --- | --- |
| `Configuration/appsettings.json` | Database path, collection/analysis parallelism, startup IOC/Sigma refresh |
| `Configuration/DetectionRules.json` | Per-detector enable flags, thresholds, Sigma options |

Disable a detector:

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

Default database: `data/investigation.db`. Log file: `data/wia.log`.

## Architecture

```text
Program.cs  →  ApplicationBootstrap (IOC + Sigma)
           →  System.CommandLine
                    │
     collect / search / timeline / analyze / ioc / sigma / export / stats
                    │
         Services (ingestion, detection, correlation, IOC, export)
                    │
         Repositories  →  SQLite (events, findings, IOC, Sigma metadata)
                    │
         EventXmlParser + EventFieldMapper  →  WindowsEvent
                    │
         Detectors (behavioral + signatures + SigmaRuleEngine)
```

Detection rules implement `IDetectionRule` and are registered in DI (`ServiceRegistration.cs`).

## PowerShell handling

Script-block text is stored and hashed. Encoded-command **text** may be decoded for analyst preview only. The application **never** executes PowerShell or launches decoded content.

## Privileges and errors

| Situation | Behavior |
| --- | --- |
| Not elevated | Limited mode: Security/Sysmon collection skipped; other features work |
| UAC elevation available | Relaunch as administrator for full log access (unless `--limited`) |
| Sysmon / PowerShell log missing | Channel skipped during collection |
| Corrupt EVTX record | Record skipped; collection continues |
| Invalid IOC JSON | Import aborted with a readable message |
| SQLite error | Logged; non-zero exit code |

## Project layout

| Folder | Role |
| --- | --- |
| `Commands/` | CLI commands |
| `Services/` | Collection, analysis, IOC feeds, export, statistics |
| `Detectors/` | Built-in and signature detectors |
| `Sigma/` | Sigma YAML parser, engine, logsource catalog |
| `Models/` | Events, findings, correlations, filters |
| `Repositories/` | SQLite access |
| `Infrastructure/` | Bootstrap, mappers, paths, elevation |
| `Exporters/` | JSON, HTML, Excel export |
| `Configuration/` | `appsettings.json`, `DetectionRules.json` |
| `WindowsIncidentAnalyzer.Tests/` | Unit and integration tests |

Russian documentation: [README.ru.md](README.ru.md).
