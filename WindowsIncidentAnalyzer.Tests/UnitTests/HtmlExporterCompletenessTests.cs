using System.Net;
using System.Reflection;
using System.Text.RegularExpressions;
using WindowsIncidentAnalyzer.Exporters;
using WindowsIncidentAnalyzer.Models;
using Xunit;

namespace WindowsIncidentAnalyzer.Tests.UnitTests;

public sealed class HtmlExporterCompletenessTests
{
    [Fact]
    public void Build_RendersEveryCsvRowFieldForFullyPopulatedExport()
    {
        var data = CreateFullyPopulatedExport();
        var html = HtmlExporter.Build(data);

        Assert.Contains("All findings", html);
        Assert.Contains("IOC matches", html);
        Assert.Contains("CVE matches", html);
        Assert.Contains("Correlations", html);
        Assert.Contains("Timeline", html);
        Assert.Contains("Related events", html);
        Assert.Contains("Statistics", html);

        AssertMarkersPresent(html, ExportRowBuilder.BuildFindingRows(data.Findings, ExportRowBuilder.BuildEventMap(data)).Single());
        AssertMarkersPresent(html, ExportRowBuilder.BuildIocRows(data.IocMatches).Single());
        AssertMarkersPresent(html, ExportRowBuilder.BuildCveRows(data.CveMatches).Single());
        AssertMarkersPresent(html, ExportRowBuilder.BuildCorrelationRows(data.Correlations).Single());
        AssertMarkersPresent(html, ExportRowBuilder.BuildTimelineRows(data.Timeline).Single());
        AssertMarkersPresent(html, ExportRowBuilder.BuildEventRows(data.Events).Single());

        Assert.Contains("4688", html);
        Assert.Contains("unique-user-marker", html);
        Assert.Contains("unique-process-marker", html);
        Assert.Contains("203.0.113.50", html);
        Assert.Contains("UNIQUE_SCRIPT_TAIL_ZZZ", html);
        Assert.Contains("UNIQUE_PROPS_TAIL_YYY", html);
        Assert.Contains("UNIQUE_RAW_XML_TAIL_XXX", html);
        Assert.Contains("UNIQUE_RAW_EVENT_TAIL_WWW", html);
    }

    [Fact]
    public void FindingsTable_HasSameColumnCountAsFindingCsvRowMap()
    {
        var expectedColumns = new FindingCsvRowMap().MemberMaps.Count;
        var html = HtmlExporter.Build(CreateFullyPopulatedExport());
        var findingsSection = ExtractSection(html, "All findings");
        var headerCells = Regex.Matches(findingsSection, "<th\\b").Count;
        var firstDataRow = Regex.Match(findingsSection, "<tbody>\\s*<tr>(.*?)</tr>", RegexOptions.Singleline);
        Assert.True(firstDataRow.Success);
        var dataCells = Regex.Matches(firstDataRow.Groups[1].Value, "<td\\b").Count;

        Assert.Equal(expectedColumns, headerCells);
        Assert.Equal(expectedColumns, dataCells);
        Assert.Equal(59, expectedColumns);
    }

    [Fact]
    public void EventsTable_HasSameColumnCountAsEventCsvRowMap()
    {
        var expectedColumns = new EventCsvRowMap().MemberMaps.Count;
        var html = HtmlExporter.Build(CreateFullyPopulatedExport());
        var eventsSection = ExtractSection(html, "Related events");
        var headerCells = Regex.Matches(eventsSection, "<th\\b").Count;
        var firstDataRow = Regex.Match(eventsSection, "<tbody>\\s*<tr>(.*?)</tr>", RegexOptions.Singleline);
        Assert.True(firstDataRow.Success);
        var dataCells = Regex.Matches(firstDataRow.Groups[1].Value, "<td\\b").Count;

        Assert.Equal(expectedColumns, headerCells);
        Assert.Equal(expectedColumns, dataCells);
        Assert.Equal(35, expectedColumns);
    }

    private static void AssertMarkersPresent(string html, object row)
    {
        foreach (var property in row.GetType().GetProperties(BindingFlags.Instance | BindingFlags.Public))
        {
            var value = property.GetValue(row);
            if (value is null)
            {
                continue;
            }

            var text = value.ToString();
            if (string.IsNullOrWhiteSpace(text))
            {
                continue;
            }

            // Numeric zeros are not distinctive markers; skip generic empties already filtered.
            if (value is int or long && Convert.ToInt64(value) == 0)
            {
                continue;
            }

            // Long fields may sit inside <pre>; still must appear encoded.
            var encoded = WebUtility.HtmlEncode(text);
            Assert.True(
                html.Contains(encoded, StringComparison.Ordinal) || html.Contains(text, StringComparison.Ordinal),
                $"Missing {row.GetType().Name}.{property.Name} value in HTML: {text[..Math.Min(80, text.Length)]}");
        }
    }

    private static string ExtractSection(string html, string heading)
    {
        var start = html.IndexOf($"<h2>{heading}</h2>", StringComparison.Ordinal);
        Assert.True(start >= 0, $"Missing section {heading}");
        var next = html.IndexOf("<section>", start + 1, StringComparison.Ordinal);
        return next < 0 ? html[start..] : html[start..next];
    }

    private static InvestigationExport CreateFullyPopulatedExport()
    {
        var evt = new WindowsEvent
        {
            Id = 42,
            ComputerName = "HOST-UNIQUE-01",
            LogName = "Security",
            ProviderName = "Microsoft-Windows-Security-Auditing",
            EventId = 4688,
            EventRecordId = 9001,
            TimeCreatedUtc = new DateTime(2026, 5, 1, 12, 30, 45, DateTimeKind.Utc),
            Level = "Information",
            User = "SUBJECT_USER",
            Domain = "SUBJECT_DOMAIN",
            TargetUserName = "TARGET_USER",
            TargetDomainName = "TARGET_DOMAIN",
            ProcessName = "unique-proc.exe",
            ProcessPath = @"C:\Tools\unique-proc.exe",
            ProcessId = 4242,
            ParentProcessName = "unique-parent.exe",
            ParentProcessId = 1111,
            CommandLine = "unique-proc.exe /full-command-line",
            ParentCommandLine = "unique-parent.exe /spawn",
            SourceIpAddress = "198.51.100.10",
            DestinationIpAddress = "203.0.113.20",
            SourcePort = 51515,
            DestinationPort = 443,
            WorkstationName = "WS-UNIQUE",
            LogonType = 3,
            ScriptBlock = new string('A', 500) + "UNIQUE_SCRIPT_TAIL_ZZZ",
            ScriptBlockHash = "SCRIPT_HASH_UNIQUE",
            Hashes = "SHA256=HASHUNIQUE001,MD5=MD5UNIQUE001",
            ProcessGuid = "{PROC-GUID-UNIQUE}",
            ParentProcessGuid = "{PARENT-GUID-UNIQUE}",
            QueryName = "unique.dns.example",
            TaskName = "UniqueScheduledTask",
            ServiceName = "UniqueService",
            Properties = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["CurrentDirectory"] = @"C:\Unique\Work",
                ["IntegrityLevel"] = "High",
                ["ElevatedToken"] = "%%1842",
                ["OriginalFileName"] = "unique-orig.exe",
                ["Signature"] = "Unique Signer LLC",
                ["TargetUserSid"] = "S-1-5-21-UNIQUE",
                ["TargetLogonId"] = "0xUNIQUELOGON",
                ["ExtraProp"] = new string('P', 500) + "UNIQUE_PROPS_TAIL_YYY"
            },
            RawXml = "<Event><System/><EventData>UNIQUE_RAW_XML_TAIL_XXX</EventData></Event>"
        };

        var finding = new SecurityFinding
        {
            Id = 7,
            RuleName = "SigmaRules",
            Title = "[Sigma] Unique Finding Title",
            Description = "Unique finding description text",
            Severity = DetectionSeverity.High,
            TimeUtc = evt.TimeCreatedUtc,
            CreatedUtc = evt.TimeCreatedUtc.AddMinutes(1),
            ComputerName = evt.ComputerName,
            User = evt.TargetUserName,
            SourceIpAddress = evt.SourceIpAddress,
            ProcessName = evt.ProcessName,
            Details = "unique-details-marker",
            RelatedEventRowIds = [evt.Id],
            Context = new FindingContext
            {
                RuleId = "rule-id-unique-111",
                RuleTitle = "Unique Rule Title",
                Category = "process_creation",
                EventType = "process_creation",
                CategoryMatchesEvent = true,
                SeverityMatchesEvent = true,
                RequestedSeverity = DetectionSeverity.Critical,
                Severity = DetectionSeverity.High,
                TimestampUtc = evt.TimeCreatedUtc,
                EventId = evt.EventId,
                EventRecordId = evt.EventRecordId,
                Provider = evt.ProviderName,
                Channel = evt.LogName,
                Host = evt.ComputerName,
                Domain = evt.TargetDomainName,
                User = evt.TargetUserName,
                UserSid = "S-1-5-21-UNIQUE",
                LogonId = "0xUNIQUELOGON",
                ProcessId = evt.ProcessId,
                ParentProcessId = evt.ParentProcessId,
                ProcessName = evt.ProcessName,
                Image = evt.ProcessPath,
                CommandLine = evt.CommandLine,
                ParentImage = evt.ParentProcessName,
                ParentCommandLine = evt.ParentCommandLine,
                WorkingDirectory = @"C:\Unique\Work",
                IntegrityLevel = "High",
                ElevationType = "%%1842",
                SourceIp = evt.SourceIpAddress,
                SourcePort = evt.SourcePort,
                DestinationIp = evt.DestinationIpAddress,
                DestinationPort = evt.DestinationPort,
                FilePath = evt.ProcessPath,
                Sha256 = "HASHUNIQUE001",
                Md5 = "MD5UNIQUE001",
                Signer = "Unique Signer LLC",
                OriginalFileName = "unique-orig.exe",
                SigmaId = "11111111-2222-3333-4444-555555555555",
                SigmaStatus = "test",
                MitreTactic = "TA0002",
                MitreTechnique = "T1059",
                MitreTechniqueName = "Command and Scripting Interpreter",
                MitreTacticName = "Execution",
                MitreUrl = "https://attack.mitre.org/techniques/T1059/",
                MitreTags = ["attack.execution", "attack.t1059"],
                MatchedSelection = "selection",
                MatchedFields = ["Image", "CommandLine"],
                MatchedValues = [evt.ProcessPath!, evt.CommandLine!],
                Condition = "selection",
                Reason = "Image endswith unique-proc.exe",
                RawEvent = "{\"id\":42,\"marker\":\"UNIQUE_RAW_EVENT_TAIL_WWW\"}",
                RawXml = evt.RawXml
            }
        };

        return new InvestigationExport
        {
            Title = "Completeness Test Export",
            GeneratedUtc = new DateTime(2026, 9, 4, 12, 0, 0, DateTimeKind.Utc),
            Findings = [finding],
            IocMatches =
            [
                new IocMatch
                {
                    IocType = "ip",
                    IocValue = "198.51.100.99",
                    EventId = 3,
                    EventRowId = evt.Id,
                    TimestampUtc = evt.TimeCreatedUtc,
                    Host = evt.ComputerName,
                    RelatedProcess = evt.ProcessName,
                    RelatedUser = evt.TargetUserName,
                    MatchedField = "SourceIpAddress"
                }
            ],
            CveMatches =
            [
                new CveMatch
                {
                    CveId = "CVE-2024-UNIQUE",
                    VulnerabilityName = "Unique Vulnerability Name",
                    ShortDescription = "Unique CVE short description",
                    VendorProject = "UniqueVendor",
                    Product = "UniqueProduct",
                    KnownRansomwareUse = "Known",
                    EventId = evt.EventId,
                    EventRowId = evt.Id,
                    TimestampUtc = evt.TimeCreatedUtc,
                    Host = evt.ComputerName,
                    RelatedProcess = evt.ProcessName,
                    RelatedUser = evt.TargetUserName,
                    MatchedField = "CommandLine"
                }
            ],
            Correlations =
            [
                new EventCorrelation
                {
                    Id = 5,
                    Scenario = "UniqueScenario",
                    Title = "Unique Correlation Title",
                    Interpretation = "Unique interpretation text",
                    Severity = DetectionSeverity.High,
                    TimeUtc = evt.TimeCreatedUtc,
                    CreatedUtc = evt.TimeCreatedUtc.AddMinutes(2),
                    User = evt.TargetUserName,
                    ComputerName = evt.ComputerName,
                    SourceIpAddress = evt.SourceIpAddress,
                    Details = "unique-correlation-details",
                    RelatedEventRowIds = [evt.Id]
                }
            ],
            Timeline =
            [
                new TimelineItem
                {
                    TimestampUtc = evt.TimeCreatedUtc,
                    EventRowId = evt.Id,
                    Host = evt.ComputerName,
                    EventId = evt.EventId,
                    Source = evt.LogName,
                    User = evt.TargetUserName,
                    Process = evt.ProcessName,
                    Ip = evt.SourceIpAddress,
                    Description = "Unique timeline description",
                    Severity = DetectionSeverity.Medium
                }
            ],
            Events = [evt],
            Statistics = new StatisticsResult
            {
                TotalEvents = 1,
                TotalFindings = 1,
                EventIdCounts = new Dictionary<int, int> { [4688] = 1 },
                UserCounts = new Dictionary<string, int> { ["unique-user-marker"] = 1 },
                ProcessCounts = new Dictionary<string, int> { ["unique-process-marker"] = 1 },
                SourceIpCounts = new Dictionary<string, int> { ["203.0.113.50"] = 1 },
                EventsByHour = new Dictionary<int, int> { [12] = 1 },
                FindingsBySeverity = new Dictionary<DetectionSeverity, int> { [DetectionSeverity.High] = 1 }
            }
        };
    }
}
