using System.Text.Json;
using WindowsIncidentAnalyzer.Models;
using WindowsIncidentAnalyzer.Persistence;
using WindowsIncidentAnalyzer.Persistence.Entities;
using Xunit;

namespace WindowsIncidentAnalyzer.Tests.UnitTests;

public sealed class EntityMappersTests
{
    private static readonly DateTime SampleTime = new(2026, 5, 10, 8, 0, 0, DateTimeKind.Utc);

    [Fact]
    public void Event_ToEntityAndBack_RoundTripsAllFields()
    {
        var evt = new WindowsEvent
        {
            Id = 10,
            ComputerName = "HOST01",
            LogName = "Security",
            ProviderName = "Provider",
            EventId = 4688,
            EventRecordId = 123,
            TimeCreatedUtc = SampleTime,
            Level = "Information",
            User = "alice",
            Domain = "CORP",
            ProcessName = "cmd.exe",
            ProcessId = 100,
            ParentProcessName = "explorer.exe",
            ParentProcessId = 50,
            CommandLine = "cmd.exe /c dir",
            SourceIpAddress = "10.0.0.1",
            DestinationIpAddress = "10.0.0.2",
            WorkstationName = "WS01",
            TargetUserName = "bob",
            TargetDomainName = "CORP",
            RawXml = "<Event/>",
            Properties = { ["SubjectUserName"] = "alice", ["ProcessId"] = "100" },
            ScriptBlock = "Get-ChildItem",
            ScriptBlockHash = "hash1",
            Hashes = "SHA256=abc",
            ProcessGuid = "{p}",
            ParentProcessGuid = "{pp}",
            ParentCommandLine = "explorer.exe",
            SourcePort = 445,
            DestinationPort = 139,
            QueryName = "query",
            TaskName = "task",
            ServiceName = "service",
            LogonType = 3,
            ProcessPath = @"C:\Windows\System32\cmd.exe"
        };

        var entity = EntityMappers.ToEntity(evt, "event-key", completenessScore: 85);
        entity.Id = evt.Id;

        var roundTrip = EntityMappers.ToDomain(entity);

        Assert.Equal(evt.Id, roundTrip.Id);
        Assert.Equal(evt.ComputerName, roundTrip.ComputerName);
        Assert.Equal(evt.LogName, roundTrip.LogName);
        Assert.Equal(evt.ProviderName, roundTrip.ProviderName);
        Assert.Equal(evt.EventId, roundTrip.EventId);
        Assert.Equal(evt.EventRecordId, roundTrip.EventRecordId);
        Assert.Equal(evt.TimeCreatedUtc, roundTrip.TimeCreatedUtc);
        Assert.Equal(evt.Level, roundTrip.Level);
        Assert.Equal(evt.User, roundTrip.User);
        Assert.Equal(evt.Domain, roundTrip.Domain);
        Assert.Equal(evt.ProcessName, roundTrip.ProcessName);
        Assert.Equal(evt.ProcessId, roundTrip.ProcessId);
        Assert.Equal(evt.ParentProcessName, roundTrip.ParentProcessName);
        Assert.Equal(evt.ParentProcessId, roundTrip.ParentProcessId);
        Assert.Equal(evt.CommandLine, roundTrip.CommandLine);
        Assert.Equal(evt.SourceIpAddress, roundTrip.SourceIpAddress);
        Assert.Equal(evt.DestinationIpAddress, roundTrip.DestinationIpAddress);
        Assert.Equal(evt.WorkstationName, roundTrip.WorkstationName);
        Assert.Equal(evt.TargetUserName, roundTrip.TargetUserName);
        Assert.Equal(evt.TargetDomainName, roundTrip.TargetDomainName);
        Assert.Equal(evt.RawXml, roundTrip.RawXml);
        Assert.Equal("alice", roundTrip.Properties["SubjectUserName"]);
        Assert.Equal("100", roundTrip.Properties["ProcessId"]);
        Assert.Equal(evt.ScriptBlock, roundTrip.ScriptBlock);
        Assert.Equal(evt.ScriptBlockHash, roundTrip.ScriptBlockHash);
        Assert.Equal(evt.Hashes, roundTrip.Hashes);
        Assert.Equal(evt.ProcessGuid, roundTrip.ProcessGuid);
        Assert.Equal(evt.ParentProcessGuid, roundTrip.ParentProcessGuid);
        Assert.Equal(evt.ParentCommandLine, roundTrip.ParentCommandLine);
        Assert.Equal(evt.SourcePort, roundTrip.SourcePort);
        Assert.Equal(evt.DestinationPort, roundTrip.DestinationPort);
        Assert.Equal(evt.QueryName, roundTrip.QueryName);
        Assert.Equal(evt.TaskName, roundTrip.TaskName);
        Assert.Equal(evt.ServiceName, roundTrip.ServiceName);
        Assert.Equal(evt.LogonType, roundTrip.LogonType);
        Assert.Equal(evt.ProcessPath, roundTrip.ProcessPath);
        Assert.Equal("event-key", entity.EventKey);
        Assert.Equal(85, entity.CompletenessScore);
    }

    [Fact]
    public void MergeRicher_PrefersNonNullSourceValuesAndUpdatesScore()
    {
        var target = new EventEntity
        {
            ComputerName = "OLD-HOST",
            LogName = "OldLog",
            ProviderName = "OldProvider",
            EventId = 1,
            EventRecordId = 10,
            CompletenessScore = 10,
            TimeCreatedUtc = SampleTime.AddDays(-1),
            User = "old-user",
            ProcessId = 1,
            PropertiesJson = "{\"keep\":\"me\"}"
        };

        var source = new WindowsEvent
        {
            ComputerName = "NEW-HOST",
            LogName = null,
            ProviderName = "NewProvider",
            EventId = 4688,
            EventRecordId = null,
            TimeCreatedUtc = SampleTime,
            User = null,
            ProcessId = 200,
            CommandLine = "new-cmd",
            Properties = { ["added"] = "value" }
        };

        EntityMappers.MergeRicher(target, source, completenessScore: 95);

        Assert.Equal("NEW-HOST", target.ComputerName);
        Assert.Equal("OldLog", target.LogName);
        Assert.Equal("NewProvider", target.ProviderName);
        Assert.Equal(4688, target.EventId);
        Assert.Equal(10L, target.EventRecordId);
        Assert.Equal(95, target.CompletenessScore);
        Assert.Equal(SampleTime, target.TimeCreatedUtc);
        Assert.Equal("old-user", target.User);
        Assert.Equal(200, target.ProcessId);
        Assert.Equal("new-cmd", target.CommandLine);
        Assert.Contains("added", target.PropertiesJson!, StringComparison.Ordinal);
    }

    [Fact]
    public void Finding_ToEntityAndBack_RoundTripsFieldsAndContext()
    {
        var finding = new SecurityFinding
        {
            Id = 7,
            RuleName = "SigmaRule",
            Title = "Suspicious activity",
            Description = "Description",
            Severity = DetectionSeverity.High,
            TimeUtc = SampleTime,
            ComputerName = "HOST01",
            User = "alice",
            SourceIpAddress = "10.0.0.5",
            ProcessName = "powershell.exe",
            Details = "Details text",
            RelatedEventRowIds = [1, 2],
            CreatedUtc = SampleTime.AddHours(1),
            Context = new FindingContext
            {
                RuleId = "rule-1",
                Host = "HOST01",
                CommandLine = "powershell -enc abc",
                EventId = 4688
            }
        };

        var entity = EntityMappers.ToEntity(finding);
        entity.Id = finding.Id;

        var roundTrip = EntityMappers.ToDomain(entity);

        Assert.Equal(finding.Id, roundTrip.Id);
        Assert.Equal(finding.RuleName, roundTrip.RuleName);
        Assert.Equal(finding.Title, roundTrip.Title);
        Assert.Equal(finding.Description, roundTrip.Description);
        Assert.Equal(DetectionSeverity.High, roundTrip.Severity);
        Assert.Equal(finding.TimeUtc, roundTrip.TimeUtc);
        Assert.Equal(finding.ComputerName, roundTrip.ComputerName);
        Assert.Equal(finding.User, roundTrip.User);
        Assert.Equal(finding.SourceIpAddress, roundTrip.SourceIpAddress);
        Assert.Equal(finding.ProcessName, roundTrip.ProcessName);
        Assert.Equal(finding.Details, roundTrip.Details);
        Assert.Equal(finding.RelatedEventRowIds, roundTrip.RelatedEventRowIds);
        Assert.Equal(finding.CreatedUtc, roundTrip.CreatedUtc);
        Assert.Equal("rule-1", roundTrip.Context.RuleId);
        Assert.Equal("HOST01", roundTrip.Context.Host);
        Assert.Equal("powershell -enc abc", roundTrip.Context.CommandLine);
        Assert.Equal(4688, roundTrip.Context.EventId);
    }

    [Fact]
    public void Finding_ToDomain_InvalidSeverity_FallsBackToInfo()
    {
        var entity = new FindingEntity
        {
            Id = 1,
            RuleName = "Rule",
            Title = "Title",
            Severity = "NotARealSeverity",
            TimeUtc = SampleTime,
            RelatedEventRowIds = "[]",
            CreatedUtc = SampleTime
        };

        var finding = EntityMappers.ToDomain(entity);

        Assert.Equal(DetectionSeverity.Info, finding.Severity);
    }

    [Fact]
    public void Correlation_ToDomain_InvalidSeverity_FallsBackToMedium()
    {
        var entity = new CorrelationEntity
        {
            Id = 1,
            Scenario = "Test",
            Title = "Title",
            Severity = "INVALID",
            TimeUtc = SampleTime,
            RelatedEventRowIds = "[]",
            CreatedUtc = SampleTime
        };

        var correlation = EntityMappers.ToDomain(entity);

        Assert.Equal(DetectionSeverity.Medium, correlation.Severity);
    }

    [Fact]
    public void Ioc_ToEntityAndBack_NormalizesTypeAndTrimsValue()
    {
        var ioc = new Ioc
        {
            Id = 3,
            Type = "  IP  ",
            Value = "  203.0.113.1  ",
            Source = "feed",
            Comment = "malicious",
            ImportedUtc = SampleTime
        };

        var entity = EntityMappers.ToEntity(ioc);
        entity.Id = ioc.Id;

        var roundTrip = EntityMappers.ToDomain(entity);

        Assert.Equal(3, roundTrip.Id);
        Assert.Equal("ip", entity.Type);
        Assert.Equal("203.0.113.1", entity.Value);
        Assert.Equal("ip", roundTrip.Type);
        Assert.Equal("203.0.113.1", roundTrip.Value);
        Assert.Equal("feed", roundTrip.Source);
        Assert.Equal("malicious", roundTrip.Comment);
        Assert.Equal(SampleTime, roundTrip.ImportedUtc);
    }

    [Fact]
    public void DeserializeIds_InvalidJson_ReturnsEmptyList()
    {
        Assert.Empty(EntityMappers.DeserializeIds("not-json"));
        Assert.Empty(EntityMappers.DeserializeIds(null));
        Assert.Empty(EntityMappers.DeserializeIds("   "));
    }

    [Fact]
    public void DeserializeIds_ValidJson_ReturnsIds()
    {
        var json = JsonSerializer.Serialize(new List<long> { 1, 5, 9 });

        Assert.Equal([1L, 5L, 9L], EntityMappers.DeserializeIds(json));
    }
}
