using Microsoft.Extensions.Options;
using WindowsIncidentAnalyzer.Configuration;
using WindowsIncidentAnalyzer.Infrastructure;
using WindowsIncidentAnalyzer.Models;
using WindowsIncidentAnalyzer.Services;
using Xunit;

namespace WindowsIncidentAnalyzer.Tests.UnitTests;

public sealed class ParallelAnalysisTests
{
    [Fact]
    public void ResolveMaxDegreeOfParallelism_Zero_UsesProcessorCount()
    {
        var degree = ParallelAnalysis.ResolveMaxDegreeOfParallelism(new AnalysisOptions());
        Assert.Equal(Math.Max(1, Environment.ProcessorCount), degree);
    }

    [Fact]
    public void ResolveMaxDegreeOfParallelism_ExplicitValue_IsRespected()
    {
        var degree = ParallelAnalysis.ResolveMaxDegreeOfParallelism(new AnalysisOptions { MaxDegreeOfParallelism = 2 });
        Assert.Equal(2, degree);
    }

    [Fact]
    public void CorrelationService_ParallelAndSequential_ProduceSameChains()
    {
        var events = BuildCorrelationEvents();
        var rules = Options.Create(new DetectionRulesOptions());
        var parallel = Options.Create(new AnalyzerOptions { Analysis = new AnalysisOptions { EnableParallelAnalysis = true, MaxDegreeOfParallelism = 4 } });
        var sequential = Options.Create(new AnalyzerOptions { Analysis = new AnalysisOptions { EnableParallelAnalysis = false } });

        var parallelService = new CorrelationService(null!, rules, parallel, Microsoft.Extensions.Logging.Abstractions.NullLogger<CorrelationService>.Instance);
        var sequentialService = new CorrelationService(null!, rules, sequential, Microsoft.Extensions.Logging.Abstractions.NullLogger<CorrelationService>.Instance);

        var parallelChains = parallelService.Correlate(events);
        var sequentialChains = sequentialService.Correlate(events);

        Assert.Equal(
            sequentialChains.Select(c => c.Scenario).OrderBy(s => s),
            parallelChains.Select(c => c.Scenario).OrderBy(s => s));
    }

    [Fact]
    public void IocDetectionService_ParallelAndSequential_ProduceSameMatches()
    {
        var events = Enumerable.Range(0, 32).Select(i => new WindowsEvent
        {
            Id = i + 1,
            EventId = 3,
            TimeCreatedUtc = DateTime.UtcNow.AddMinutes(i),
            SourceIpAddress = i % 2 == 0 ? "10.0.0.8" : "192.168.1.1",
            ProcessName = i % 3 == 0 ? "mimikatz.exe" : "explorer.exe"
        }).ToList();

        var iocs = new[]
        {
            new Ioc { Type = "ip", Value = "10.0.0.8" },
            new Ioc { Type = "filename", Value = "mimikatz.exe" }
        };

        var parallel = new IocDetectionService(
            null!,
            null!,
            Options.Create(new AnalyzerOptions { Analysis = new AnalysisOptions { EnableParallelAnalysis = true, MaxDegreeOfParallelism = 4 } }),
            Microsoft.Extensions.Logging.Abstractions.NullLogger<IocDetectionService>.Instance);
        var sequential = new IocDetectionService(
            null!,
            null!,
            Options.Create(new AnalyzerOptions { Analysis = new AnalysisOptions { EnableParallelAnalysis = false } }),
            Microsoft.Extensions.Logging.Abstractions.NullLogger<IocDetectionService>.Instance);

        var parallelMatches = parallel.Scan(events, iocs);
        var sequentialMatches = sequential.Scan(events, iocs);

        Assert.Equal(sequentialMatches.Count, parallelMatches.Count);
        Assert.Equal(
            sequentialMatches.Select(m => $"{m.IocType}:{m.IocValue}:{m.EventRowId}").OrderBy(s => s),
            parallelMatches.Select(m => $"{m.IocType}:{m.IocValue}:{m.EventRowId}").OrderBy(s => s));
    }

    private static List<WindowsEvent> BuildCorrelationEvents()
    {
        var baseTime = DateTime.UtcNow;
        return
        [
            new WindowsEvent { Id = 1, EventId = 4625, TimeCreatedUtc = baseTime, TargetUserName = "admin", SourceIpAddress = "10.0.0.5" },
            new WindowsEvent { Id = 2, EventId = 4625, TimeCreatedUtc = baseTime.AddMinutes(1), TargetUserName = "admin", SourceIpAddress = "10.0.0.5" },
            new WindowsEvent { Id = 3, EventId = 4625, TimeCreatedUtc = baseTime.AddMinutes(2), TargetUserName = "admin", SourceIpAddress = "10.0.0.5" },
            new WindowsEvent { Id = 4, EventId = 4625, TimeCreatedUtc = baseTime.AddMinutes(3), TargetUserName = "admin", SourceIpAddress = "10.0.0.5" },
            new WindowsEvent { Id = 5, EventId = 4625, TimeCreatedUtc = baseTime.AddMinutes(4), TargetUserName = "admin", SourceIpAddress = "10.0.0.5" },
            new WindowsEvent { Id = 6, EventId = 4624, TimeCreatedUtc = baseTime.AddMinutes(5), TargetUserName = "admin", SourceIpAddress = "10.0.0.5" },
            new WindowsEvent { Id = 7, EventId = 4672, TimeCreatedUtc = baseTime.AddMinutes(6), User = "admin" },
            new WindowsEvent { Id = 8, EventId = 4720, TimeCreatedUtc = baseTime.AddMinutes(10), TargetUserName = "backdoor" },
            new WindowsEvent { Id = 9, EventId = 4728, TimeCreatedUtc = baseTime.AddMinutes(11), RawXml = "backdoor", TargetUserName = "Administrators" },
            new WindowsEvent { Id = 10, EventId = 4624, TimeCreatedUtc = baseTime.AddMinutes(12), TargetUserName = "backdoor" }
        ];
    }
}
