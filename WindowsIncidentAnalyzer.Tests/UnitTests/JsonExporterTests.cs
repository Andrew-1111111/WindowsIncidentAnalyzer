using System.Text.Json;
using WindowsIncidentAnalyzer.Exporters;
using WindowsIncidentAnalyzer.Models;
using Xunit;

namespace WindowsIncidentAnalyzer.Tests.UnitTests;

public sealed class JsonExporterTests
{
    [Fact]
    public void CreateSerializerOptions_PreservesCyrillicLiterals()
    {
        var json = JsonSerializer.Serialize(
            new StatisticsResult
            {
                UserCounts = new Dictionary<string, int>
                {
                    ["СИСТЕМА"] = 11950,
                    ["Администраторы"] = 693
                }
            },
            JsonExporter.CreateSerializerOptions());

        Assert.Contains("СИСТЕМА", json);
        Assert.Contains("Администраторы", json);
        Assert.DoesNotContain("\\u0421", json);
        Assert.DoesNotContain("\\u0410", json);
    }

    [Fact]
    public void InvestigationExport_SerializesFullAnalysisPayload()
    {
        var export = new InvestigationExport
        {
            Filter = new EventQueryFilter { User = "alice", Limit = 100 },
            Findings =
            [
                new SecurityFinding
                {
                    RuleName = "SigmaRules",
                    Title = "Test",
                    Severity = DetectionSeverity.High,
                    TimeUtc = DateTime.UtcNow,
                    Context = new FindingContext { EventType = "process_creation", SigmaId = "abc" }
                }
            ],
            Events =
            [
                new WindowsEvent
                {
                    Id = 42,
                    EventId = 4688,
                    ComputerName = "HOST01",
                    Properties = new Dictionary<string, string> { ["CommandLine"] = "cmd.exe" }
                }
            ],
            IocMatches = [new IocMatch { IocType = "ip", IocValue = "1.2.3.4", EventRowId = 42, EventId = 3 }],
            Correlations =
            [
                new EventCorrelation
                {
                    Scenario = "BruteForce",
                    Title = "Chain",
                    Severity = DetectionSeverity.High,
                    RelatedEventRowIds = [42]
                }
            ],
            Timeline = [new TimelineItem { EventRowId = 42, EventId = 4688, Description = "process created" }]
        };

        var json = JsonSerializer.Serialize(export, JsonExporter.CreateSerializerOptions());

        Assert.Contains("\"filter\"", json);
        Assert.Contains("\"events\"", json);
        Assert.Contains("\"process_creation\"", json);
        Assert.Contains("\"relatedEventRowIds\"", json);
        Assert.Contains("\"properties\"", json);
        Assert.Contains("\"timeline\"", json);
    }
}
