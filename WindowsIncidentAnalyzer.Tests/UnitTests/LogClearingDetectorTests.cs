using Microsoft.Extensions.Options;
using WindowsIncidentAnalyzer.Configuration;
using WindowsIncidentAnalyzer.Detectors;
using WindowsIncidentAnalyzer.Models;
using WindowsIncidentAnalyzer.Services;
using WindowsIncidentAnalyzer.Tests.Fixtures;
using Xunit;

namespace WindowsIncidentAnalyzer.Tests.UnitTests;

public sealed class LogClearingDetectorTests
{
    private readonly EventXmlParser _parser = new();
    private readonly LogClearingDetector _detector = new(Options.Create(new DetectionRulesOptions
    {
        LogClearing = new LogClearingOptions { Enabled = true }
    }));

    [Fact]
    public void Analyze_SecurityLogCleared1102_ReportsCritical()
    {
        var evt = _parser.Parse(EventXmlFixtures.SecurityEvent(
            1102,
            "2026-08-01T12:00:00.0000000Z",
            "LAB-HOST-01",
            ("SubjectUserName", "labadmin"),
            ("SubjectDomainName", "LAB")));

        var findings = _detector.Analyze([evt]).ToList();

        Assert.Single(findings);
        Assert.Contains(findings, f => f.Title.Contains("Security event log was cleared", StringComparison.OrdinalIgnoreCase));
        Assert.Equal(DetectionSeverity.Critical, findings[0].Severity);
    }

    [Fact]
    public void Analyze_EventlogChannel104_ReportsHigh()
    {
        var evt = _parser.Parse(EventXmlFixtures.EventlogChannelCleared("2026-08-01T12:00:00.0000000Z"));

        var findings = _detector.Analyze([evt]).ToList();

        Assert.Single(findings);
        Assert.Contains(findings, f => f.Title.Contains("Windows event channel was cleared", StringComparison.OrdinalIgnoreCase));
        Assert.Equal(DetectionSeverity.High, findings[0].Severity);
    }

    [Fact]
    public void Analyze_NonEventlog104_IsIgnored()
    {
        var evt = _parser.Parse(EventXmlFixtures.SecurityEvent(
            104,
            "2026-08-01T12:00:00.0000000Z",
            "LAB-HOST-01",
            ("SubjectUserName", "labadmin"),
            ("SubjectDomainName", "LAB")));

        Assert.Empty(_detector.Analyze([evt]));
    }

    [Fact]
    public void Analyze_DisabledRule_ReturnsNothing()
    {
        var detector = new LogClearingDetector(Options.Create(new DetectionRulesOptions
        {
            LogClearing = new LogClearingOptions { Enabled = false }
        }));
        var events = new[]
        {
            _parser.Parse(EventXmlFixtures.SecurityEvent(1102, "2026-08-01T12:00:00.0000000Z", "LAB-HOST-01",
                ("SubjectUserName", "labadmin"))),
            _parser.Parse(EventXmlFixtures.EventlogChannelCleared("2026-08-01T12:01:00.0000000Z"))
        };

        Assert.Empty(detector.Analyze(events));
    }
}
