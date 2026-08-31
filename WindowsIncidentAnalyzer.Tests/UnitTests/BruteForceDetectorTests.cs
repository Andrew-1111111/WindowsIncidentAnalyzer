using Microsoft.Extensions.Options;
using WindowsIncidentAnalyzer.Configuration;
using WindowsIncidentAnalyzer.Detectors;
using WindowsIncidentAnalyzer.Services;
using WindowsIncidentAnalyzer.Tests.Fixtures;
using Xunit;

namespace WindowsIncidentAnalyzer.Tests.UnitTests;

public sealed class BruteForceDetectorTests
{
    private readonly EventXmlParser _parser = new();
    private readonly BruteForceDetector _detector = new(Options.Create(new DetectionRulesOptions
    {
        BruteForce = new BruteForceOptions
        {
            Enabled = true,
            FailedAttemptsThreshold = 5,
            TimeWindowMinutes = 5
        }
    }));

    [Fact]
    public void Analyze_FiveFailuresThenSuccess_ReportsSuccessfulBruteForce()
    {
        var start = new DateTime(2026, 8, 1, 12, 0, 0, DateTimeKind.Utc);
        var events = Enumerable.Range(0, 5)
            .Select(i => _parser.Parse(EventXmlFixtures.FailedLogon(
                start.AddSeconds(i * 10).ToString("o"), "labuser", "10.0.0.50")))
            .ToList();
        events.Add(_parser.Parse(EventXmlFixtures.SuccessfulLogon(
            start.AddMinutes(1).ToString("o"), "labuser", "10.0.0.50")));

        var findings = _detector.Analyze(events).ToList();
        Assert.Contains(findings, f => f.Title.Contains("successful brute force", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(findings, f => f.Severity == Models.DetectionSeverity.High);
    }

    [Fact]
    public void Analyze_FiveFailuresWithoutSuccess_ReportsMedium()
    {
        var start = new DateTime(2026, 8, 1, 12, 0, 0, DateTimeKind.Utc);
        var events = Enumerable.Range(0, 5)
            .Select(i => _parser.Parse(EventXmlFixtures.FailedLogon(
                start.AddSeconds(i * 10).ToString("o"), "labuser", "10.0.0.50")))
            .ToList();

        var findings = _detector.Analyze(events).ToList();
        Assert.Contains(findings, f => f.Title.Contains("Possible brute force", StringComparison.OrdinalIgnoreCase));
        Assert.All(findings, f => Assert.NotEqual(Models.DetectionSeverity.High, f.Severity));
    }

    [Fact]
    public void Analyze_DisabledRule_ReturnsNothing()
    {
        var detector = new BruteForceDetector(Options.Create(new DetectionRulesOptions
        {
            BruteForce = new BruteForceOptions { Enabled = false }
        }));
        var events = new[]
        {
            _parser.Parse(EventXmlFixtures.FailedLogon("2026-08-01T12:00:00.0000000Z", "labuser", "10.0.0.50"))
        };
        Assert.Empty(detector.Analyze(events));
    }
}
