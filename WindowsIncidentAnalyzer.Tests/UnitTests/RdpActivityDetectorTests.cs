using Microsoft.Extensions.Options;
using WindowsIncidentAnalyzer.Configuration;
using WindowsIncidentAnalyzer.Detectors;
using WindowsIncidentAnalyzer.Models;
using WindowsIncidentAnalyzer.Services;
using WindowsIncidentAnalyzer.Tests.Fixtures;
using Xunit;

namespace WindowsIncidentAnalyzer.Tests.UnitTests;

public sealed class RdpActivityDetectorTests
{
    private readonly EventXmlParser _parser = new();
    private readonly RdpActivityDetector _detector = new(Options.Create(new DetectionRulesOptions
    {
        RdpActivity = new RdpActivityOptions { Enabled = true }
    }));

    [Fact]
    public void Analyze_LogonType10_ReportsRdpActivity()
    {
        var evt = _parser.Parse(EventXmlFixtures.SuccessfulLogon(
            "2026-08-01T12:00:00.0000000Z", "labuser", "10.0.0.50", logonType: 10));

        var findings = _detector.Analyze([evt]).ToList();

        Assert.Single(findings);
        Assert.Contains(findings, f => f.Title.Contains("RDP logon", StringComparison.OrdinalIgnoreCase));
        Assert.Equal(DetectionSeverity.Low, findings[0].Severity);
    }

    [Fact]
    public void Analyze_OtherLogonTypes_AreIgnored()
    {
        var events = new[]
        {
            _parser.Parse(EventXmlFixtures.SuccessfulLogon(
                "2026-08-01T12:00:00.0000000Z", "labuser", "10.0.0.50", logonType: 3)),
            _parser.Parse(EventXmlFixtures.SuccessfulLogon(
                "2026-08-01T12:01:00.0000000Z", "labuser", "10.0.0.50", logonType: 2))
        };

        Assert.Empty(_detector.Analyze(events));
    }

    [Fact]
    public void Analyze_MachineAccount_IsFiltered()
    {
        var evt = _parser.Parse(EventXmlFixtures.SuccessfulLogon(
            "2026-08-01T12:00:00.0000000Z",
            "LAB-HOST-01$",
            "10.0.0.50",
            logonType: 10,
            targetSid: "S-1-5-21-1000-1000-1000-1000"));

        Assert.Empty(_detector.Analyze([evt]));
    }

    [Fact]
    public void Analyze_DisabledRule_ReturnsNothing()
    {
        var detector = new RdpActivityDetector(Options.Create(new DetectionRulesOptions
        {
            RdpActivity = new RdpActivityOptions { Enabled = false }
        }));
        var evt = _parser.Parse(EventXmlFixtures.SuccessfulLogon(
            "2026-08-01T12:00:00.0000000Z", "labuser", "10.0.0.50", logonType: 10));

        Assert.Empty(detector.Analyze([evt]));
    }
}
