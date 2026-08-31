using Microsoft.Extensions.Options;
using WindowsIncidentAnalyzer.Configuration;
using WindowsIncidentAnalyzer.Detectors;
using WindowsIncidentAnalyzer.Models;
using WindowsIncidentAnalyzer.Services;
using WindowsIncidentAnalyzer.Sigma;
using WindowsIncidentAnalyzer.Sigma.Models;
using Xunit;

namespace WindowsIncidentAnalyzer.Tests.UnitTests;

public sealed class SigmaRuleDetectorTests
{
    private const string WhoamiRule = """
        title: Whoami Execution
        id: 11111111-1111-1111-1111-111111111101
        status: test
        tags:
          - attack.discovery
          - attack.t1033
        logsource:
          product: windows
          category: process_creation
        detection:
          selection:
            Image|endswith: '\whoami.exe'
          condition: selection
        level: medium
        """;

    [Fact]
    public void Analyze_PopulatesStructuredContextAndLegacyDetails()
    {
        var rule = new SigmaYamlParser().ParseDocuments(WhoamiRule, "sample.yml").Single();
        var service = new StubSigmaRuleService([rule]);
        var detector = new SigmaRuleDetector(service, new SigmaRuleEngine(), CreateEnabledOptions());
        var evt = new WindowsEvent
        {
            Id = 42,
            EventId = 4688,
            LogName = "Security",
            ProviderName = "Microsoft-Windows-Security-Auditing",
            TimeCreatedUtc = new DateTime(2026, 8, 29, 10, 0, 0, DateTimeKind.Utc),
            ComputerName = "HOST01",
            TargetUserName = "DOMAIN\\alice",
            ProcessPath = @"C:\Windows\System32\whoami.exe",
            ProcessName = "whoami.exe",
            CommandLine = "whoami /all",
            ParentProcessName = "cmd.exe",
            RawXml = "<Event><System/></Event>"
        };

        var finding = detector.Analyze([evt]).Single();
        var ctx = finding.Context;

        Assert.Equal(4688, ctx.EventId);
        Assert.Equal("Security", ctx.Channel);
        Assert.Equal("Microsoft-Windows-Security-Auditing", ctx.Provider);
        Assert.Equal("whoami /all", ctx.CommandLine);
        Assert.Equal("HOST01", ctx.Host);
        Assert.Equal("DOMAIN\\alice", ctx.User);
        Assert.Equal("11111111-1111-1111-1111-111111111101", ctx.SigmaId);
        Assert.Equal("selection", ctx.MatchedSelection);
        Assert.Contains("Image", ctx.MatchedFields);
        Assert.Contains(@"C:\Windows\System32\whoami.exe", ctx.MatchedValues);
        Assert.Equal("selection", ctx.Condition);
        Assert.Contains("Image endswith", ctx.Reason);
        Assert.Equal("attack.t1033", ctx.MitreTechnique);
        Assert.NotNull(ctx.RawXml);
        Assert.NotNull(ctx.RawEvent);
        Assert.Contains("sigmaId=", finding.Details);
        Assert.Contains(finding.RelatedEventRowIds, id => id == 42);
    }

    private sealed class StubSigmaRuleService(IReadOnlyList<SigmaRule> rules) : ISigmaRuleService
    {
        public Task EnsureLoadedAsync(CancellationToken cancellationToken) => Task.CompletedTask;

        public IReadOnlyList<SigmaRule> GetRules() => rules;

        public Task<int> LoadFromDirectoryAsync(string directory, CancellationToken cancellationToken) =>
            Task.FromResult(rules.Count);

        public Task<int> UpdateFromSigmaHqAsync(CancellationToken cancellationToken) =>
            Task.FromResult(rules.Count);
    }

    private static IOptions<DetectionRulesOptions> CreateEnabledOptions() =>
        Options.Create(new DetectionRulesOptions
        {
            SigmaRules = new SigmaRulesOptions { Enabled = true }
        });
}
