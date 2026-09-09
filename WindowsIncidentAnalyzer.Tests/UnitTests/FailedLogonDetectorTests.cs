using Microsoft.Extensions.Options;
using WindowsIncidentAnalyzer.Configuration;
using WindowsIncidentAnalyzer.Detectors;
using WindowsIncidentAnalyzer.Models;
using WindowsIncidentAnalyzer.Services;
using WindowsIncidentAnalyzer.Tests.Fixtures;
using Xunit;

namespace WindowsIncidentAnalyzer.Tests.UnitTests;

public sealed class FailedLogonDetectorTests
{
    private readonly EventXmlParser _parser = new();
    private readonly FailedLogonDetector _detector = new(Options.Create(new DetectionRulesOptions
    {
        FailedLogon = new FailedLogonOptions
        {
            Enabled = true,
            ClusterThreshold = 3
        }
    }));

    [Fact]
    public void Analyze_AtClusterThreshold_ReportsCluster()
    {
        var start = new DateTime(2026, 8, 1, 12, 0, 0, DateTimeKind.Utc);
        var events = Enumerable.Range(0, 3)
            .Select(i => _parser.Parse(EventXmlFixtures.FailedLogon(
                start.AddSeconds(i * 5).ToString("o"), "labuser", "10.0.0.50")))
            .ToList();

        var findings = _detector.Analyze(events).ToList();

        Assert.Single(findings);
        Assert.Contains(findings, f => f.Title.Contains("Failed logons for labuser", StringComparison.OrdinalIgnoreCase));
        Assert.Equal(DetectionSeverity.Low, findings[0].Severity);
    }

    [Fact]
    public void Analyze_BelowClusterThreshold_ReturnsNothing()
    {
        var start = new DateTime(2026, 8, 1, 12, 0, 0, DateTimeKind.Utc);
        var events = Enumerable.Range(0, 2)
            .Select(i => _parser.Parse(EventXmlFixtures.FailedLogon(
                start.AddSeconds(i * 5).ToString("o"), "labuser", "10.0.0.50")))
            .ToList();

        Assert.Empty(_detector.Analyze(events));
    }

    [Fact]
    public void Analyze_SameAccountDifferentIps_ProducesSeparateClusters()
    {
        var time = "2026-08-01T12:00:00.0000000Z";
        var events = new[]
        {
            _parser.Parse(EventXmlFixtures.FailedLogon(time, "labuser", "10.0.0.50")),
            _parser.Parse(EventXmlFixtures.FailedLogon(time, "labuser", "10.0.0.50")),
            _parser.Parse(EventXmlFixtures.FailedLogon(time, "labuser", "10.0.0.50")),
            _parser.Parse(EventXmlFixtures.FailedLogon(time, "labuser", "10.0.0.60")),
            _parser.Parse(EventXmlFixtures.FailedLogon(time, "labuser", "10.0.0.60")),
            _parser.Parse(EventXmlFixtures.FailedLogon(time, "labuser", "10.0.0.60"))
        };

        var findings = _detector.Analyze(events).ToList();

        Assert.Equal(2, findings.Count);
    }

    [Fact]
    public void Analyze_DisabledRule_ReturnsNothing()
    {
        var detector = new FailedLogonDetector(Options.Create(new DetectionRulesOptions
        {
            FailedLogon = new FailedLogonOptions { Enabled = false }
        }));
        var events = Enumerable.Range(0, 5)
            .Select(_ => _parser.Parse(EventXmlFixtures.FailedLogon(
                "2026-08-01T12:00:00.0000000Z", "labuser", "10.0.0.50")))
            .ToList();

        Assert.Empty(detector.Analyze(events));
    }
}
