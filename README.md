# Windows Incident Analyzer

**Russian version:** [README.ru.md](README.ru.md)

Console application for **defensive** Windows Event Log analysis: collection, search, timeline construction, detection, Sigma rules, IOC matching, CVE (CISA KEV) scanning, MITRE ATT&CK enrichment, correlation, and export.

The tool is intended for incident response, DFIR, and threat hunting on systems you are authorized to investigate. It does **not** exploit vulnerabilities, bypass security controls, or perform remote attacks.

## Features

- Live collection from Windows event log channels (default curated set, or **all available** channels / a single channel / EVTX import)
- SQLite storage via **EF Core** with normalized event fields, property bags, findings, IOC, and CVE catalogs
- **19 detection engines**: behavioral rules, known-threat signatures, and **Sigma** (Hayabusa-curated rule set)
- Structured findings (`FindingContext`) with event metadata, Sigma match details, and MITRE tags (enriched from local ATT&CK data)
- Event-type and severity validation (category / CRIT–HIGH alignment with the source event)
- IOC import from JSON and automatic refresh from public defensive feeds
- Automatic download of Sigma rules (Hayabusa), MITRE ATT&CK, and CISA KEV on startup (cached)
- Correlation chains across authentication, account creation, persistence, and PowerShell activity
- Export to **JSON**, **HTML**, and **Excel (.xlsx)** with full investigation payload (findings, IOC/CVE, correlations, timeline, related events, statistics)
- Interactive `wia>` console when launched without arguments
- Russian and English Windows log names (`Security` / `Безопасность`, etc.)

## Requirements

- Windows (Event Log APIs)
- [.NET 9 SDK](https://dotnet.microsoft.com/download)
- **Administrator** privileges for the **Security** log and Sysmon (EVTX, Application, System, PowerShell, search, analyze, IOC, CVE, and export work without elevation)

## Build

```bash
dotnet build
dotnet test
```

The test suite currently includes **427** tests. The compiled executable is named `wia.exe`. Runtime data and logs are stored next to the executable under `data/`.

### Local publish variants

| Variant | Command | Notes |
| --- | --- | --- |
| **AnyCPU** (framework-dependent) | `dotnet publish -c Release` | Portable build; requires [.NET 9 runtime](https://dotnet.microsoft.com/download) |
| **x64** (framework-dependent) | `dotnet publish -c Release -r win-x64 --self-contained false` | 64-bit Windows; requires [.NET 9 runtime](https://dotnet.microsoft.com/download) |
| **x64 self-contained** | `dotnet publish -c Release -r win-x64 --self-contained true` | 64-bit Windows; bundles the .NET runtime |

### GitHub Actions

Every push and pull request to `main` / `master` runs [.github/workflows/build.yml](.github/workflows/build.yml) on `windows-latest`:

1. Restores dependencies and runs the test suite.
2. Publishes all three variants above as ZIP artifacts.

Download CI builds from **Actions → latest workflow run → Artifacts**:

| Artifact | Description |
| --- | --- |
| `wia-anycpu-fdd` | Framework-dependent AnyCPU build |
| `wia-win-x64-fdd` | Framework-dependent x64 build |
| `wia-win-x64-self-contained` | Self-contained x64 build (no separate runtime install) |

You can also trigger a build manually via **Actions → Build → Run workflow**.

### GitHub Releases

Pushing a **version tag** creates a [GitHub Release](https://docs.github.com/en/repositories/releasing-projects-on-github/managing-releases-in-a-repository) with all three ZIP files attached:

```bash
git tag v1.1.0
git push origin v1.1.0
```

Use tags in the form `v*` (for example `v1.1.0`, `v1.2.3-beta`). The release job runs only on tag pushes (not on ordinary `master` pushes). After the workflow finishes, open **Releases** on the repository page.

| Package | When to use |
| --- | --- |
| `wia-win-x64-self-contained.zip` | Recommended — no separate .NET install |
| `wia-win-x64-fdd.zip` | Smaller download if .NET 9 is already installed |
| `wia-anycpu-fdd.zip` | Portable framework-dependent build |

## Run

```bash
# Interactive shell (wia> prompt)
wia

# Or single commands
wia collect --hours 24
wia analyze
wia export --format html --output data/report.html
```

Skip online threat-intelligence refresh on startup (offline / fast start):

```bash
wia --skip-bootstrap analyze
```

On startup (unless help/version), the tool prints a short **investigation database summary** (event count, time range, findings, correlations, incidents, IOC/CVE records). Threat-intel download can still be skipped with `--skip-bootstrap`.

## Startup and threat intelligence

On launch, the application can automatically:

1. Download and import public **IOC feeds** (default: every 6 hours)
2. Download **Hayabusa** curated Sigma/native rules into `data/sigma-rules/` (default: every 24 hours)
3. Download **MITRE ATT&CK** enterprise bundle into `data/mitre/` (default: every 7 days)
4. Download **CISA Known Exploited Vulnerabilities** catalog into SQLite (default: every 7 days)

Settings in `Configuration/appsettings.json`:

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

When feeds are cached, startup shows IOC, Sigma, MITRE, and CVE counts and the next refresh time.

## Commands

| Command | Purpose |
| --- | --- |
| `collect` | Read live channels or a read-only EVTX file into SQLite |
| `search` | Query collected events |
| `timeline` | Chronological view, optional export |
| `analyze` | Detection rules + MITRE enrichment + IOC/CVE scan + correlation |
| `ioc import` / `ioc update` / `ioc scan` | Load, refresh, and match indicators |
| `sigma load` / `sigma update` / `sigma list` / `sigma stats` | Manage Sigma rules |
| `mitre load` / `mitre update` / `mitre lookup` / `mitre stats` | MITRE ATT&CK database |
| `cve load` / `cve update` / `cve lookup` / `cve scan` / `cve stats` | CISA KEV CVE catalog |
| `export` | JSON / HTML / Excel report (supports the same time/entity filters as search) |
| `stats` | Event ID, user, process, IP, and finding counts |

Global time filters (most commands): `--hours`, `--from`, `--to`, `--date`, `--user`, `--ip`, `--process`, `--event-id`, `--keyword`, `--limit`.

### Collect

```bash
wia collect --log Security
wia collect --log all --hours 24
wia collect --log Sysmon --hours 24
wia collect --date 2026-08-29
wia collect --from "2026-08-01 00:00:00" --to "2026-08-02 00:00:00"
wia collect --event-id 4624,4625,4688
wia collect --evtx "C:\Evidence\Security.evtx" --batch-size 500 --limit 100000
```

If `--log` is omitted, default channels depend on `CollectAllLogs` in `appsettings.json` (`false` = Security, System, Application, PowerShell, Sysmon; `true` = every available channel). Use `--log all` to force all channels, or `--log Security` / `Sysmon` / etc. for a single channel. Channels that cannot be opened (permissions, missing provider) are skipped.

By default, `collect` reads **all recorded events** with no time window and no event cap. Use `--hours`, `--from` / `--to`, or `--date` to narrow the time range, and `--limit` to cap how many events are ingested. Parallelism is controlled by root `MaxDegreeOfParallelism` (`0` = unlimited, `1` = sequential, `N` = cap). Stuck channels time out after `ChannelReadTimeoutSeconds`.

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

Runs all enabled detectors, MITRE enrichment, IOC/CVE matching, and correlation. Findings are stored in SQLite and printed in a **list format** (not a wide table):

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

Rules are downloaded from the [Hayabusa rules](https://github.com/Yamato-Security/hayabusa-rules) archive (Sigma + native YAML). They are evaluated during `analyze` when `SigmaRules.Enabled` is true in `DetectionRules.json`. Matches populate `FindingContext` (matched fields/values, condition, MITRE tags, Sigma ID). Technique/tactic IDs are enriched with human-readable names from the local ATT&CK database.

### MITRE ATT&CK

```bash
wia mitre update
wia mitre load data/mitre/enterprise-attack.json
wia mitre lookup T1033
wia mitre lookup attack.discovery
wia mitre stats
```

Source: [mitre/cti](https://github.com/mitre/cti) `enterprise-attack.json` (STIX 2.1). During `analyze` and `export`, Sigma MITRE tags are resolved to technique names, tactic names, and ATT&CK URLs in `FindingContext`.

### CVE (CISA KEV)

```bash
wia cve update
wia cve load data/cve/known_exploited_vulnerabilities.json
wia cve lookup CVE-2024-1234
wia cve scan
wia cve stats
```

Source: [CISA Known Exploited Vulnerabilities catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog). `cve scan` and `analyze` search collected events for CVE IDs that appear in the catalog (command lines, script blocks, raw XML, properties).

### Export

```bash
wia export --format json --output data/report.json
wia export --format html --output data/report.html
wia export --format csv --output data/investigation.csv
wia export --hours 24 --user admin --format html
wia stats
```

#### JSON

Single file with the full investigation payload:

- `filter` — query parameters used for export
- `statistics` — counts by severity, event ID, user, process, IP, hour
- `findings` — with complete `context` (event fields, Sigma, MITRE, raw event JSON, raw XML)
- `correlations`, `iocMatches`, `cveMatches`, `timeline`
- `events` — all normalized Windows events referenced by the above

UTF-8 with readable Cyrillic (`UnsafeRelaxedJsonEscaping`).

#### HTML

Self-contained dark-theme report (no CDN):

- Severity cards; Critical/High and all findings (same **59** columns as Excel)
- IOC matches, CVE matches, correlations, timeline
- Related events table (**35** columns) including process, network, script block, properties JSON, and raw XML
- Long text fields (script blocks, raw JSON/XML, large property bags) are shown in full via collapsible blocks
- Statistics (top event IDs, users, processes, IPs, events by hour)

#### CSV (`--format csv`)

Writes **Excel `.xlsx`** files with bold centered headers and auto-filter:

| File | Contents |
| --- | --- |
| `*-findings.xlsx` | 59 columns: severity, IDs, rule metadata, event type, validation flags, process/network/file fields, Sigma/MITRE, raw evidence |
| `*-timeline.xlsx` | Timeline items + event row ID |
| `*-iocs.xlsx` | IOC matches + event row ID |
| `*-cves.xlsx` | CVE matches (CISA KEV) + event row ID |
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

Thousands of Hayabusa/Sigma rules with logsource matching, field modifiers, and condition evaluation. Findings use `RuleName = SigmaRules` and detailed `FindingContext`.

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
| `Configuration/appsettings.json` | Database path, `MaxDegreeOfParallelism`, collection options, startup IOC/Sigma/MITRE/CVE refresh |
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
Program.cs  →  ApplicationBootstrap (DB summary + IOC/Sigma/MITRE/CVE)
           →  System.CommandLine
                    │
     collect / search / timeline / analyze / ioc / sigma / mitre / cve / export / stats
                    │
         Services (ingestion, detection, correlation, IOC/CVE, MITRE, export)
                    │
         Repositories  →  EF Core / SQLite (Persistence/)
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
| `Services/` | Collection, analysis, IOC/CVE feeds, MITRE, export, statistics |
| `Detectors/` | Built-in and signature detectors |
| `Sigma/` | Sigma YAML parser, engine, logsource catalog |
| `Mitre/` | ATT&CK STIX and CISA KEV parsers |
| `Models/` | Events, findings, correlations, filters |
| `Persistence/` | EF Core `DbContext`, entities, mappers |
| `Repositories/` | Data access over EF Core |
| `Infrastructure/` | Bootstrap, schema upgrades, paths, elevation, HTTP resilience |
| `Exporters/` | JSON, HTML, Excel export |
| `Configuration/` | `appsettings.json`, `DetectionRules.json` |
| `WindowsIncidentAnalyzer.Tests/` | Unit and integration tests |
