using Microsoft.Extensions.Options;
using WindowsIncidentAnalyzer.Configuration;
using WindowsIncidentAnalyzer.Detectors;
using WindowsIncidentAnalyzer.Models;
using WindowsIncidentAnalyzer.Services;
using WindowsIncidentAnalyzer.Tests.Fixtures;
using Xunit;

namespace WindowsIncidentAnalyzer.Tests.UnitTests;

public sealed class SuccessfulLogonDetectorTests
{
    private readonly EventXmlParser _parser = new();
    private readonly SuccessfulLogonDetector _detector = new(Options.Create(new DetectionRulesOptions
    {
        SuccessfulLogon = new SuccessfulLogonOptions { Enabled = true }
    }));

    [Theory]
    [InlineData(3, "Network", DetectionSeverity.Info)]
    [InlineData(8, "NetworkCleartext", DetectionSeverity.Low)]
    [InlineData(10, "RemoteInteractive (RDP)", DetectionSeverity.Low)]
    [InlineData(11, "CachedRemoteInteractive", DetectionSeverity.Info)]
    public void Analyze_RemoteLogonTypes_ReportExpectedTitleAndSeverity(
        int logonType,
        string logonName,
        DetectionSeverity expectedSeverity)
    {
        var evt = _parser.Parse(EventXmlFixtures.SuccessfulLogon(
            "2026-08-01T12:00:00.0000000Z", "labuser", "10.0.0.50", logonType: logonType));

        var findings = _detector.Analyze([evt]).ToList();

        Assert.Single(findings);
        Assert.Contains(findings, f => f.Title.Contains($"Successful {logonName} logon", StringComparison.OrdinalIgnoreCase));
        Assert.Equal(expectedSeverity, findings[0].Severity);
    }

    [Fact]
    public void Analyze_ExplicitCredential4648_ReportsLow()
    {
        var evt = _parser.Parse(EventXmlFixtures.SecurityEvent(
            4648,
            "2026-08-01T12:00:00.0000000Z",
            "LAB-HOST-01",
            ("SubjectUserSid", "S-1-5-21-1000-1000-1000-1105"),
            ("SubjectUserName", "labuser"),
            ("SubjectDomainName", "LAB"),
            ("TargetUserSid", "S-1-5-21-1000-1000-1000-1105"),
            ("TargetUserName", "labadmin"),
            ("TargetDomainName", "LAB"),
            ("ProcessName", @"C:\Windows\System32\runas.exe"),
            ("IpAddress", "10.0.0.50")));

        var findings = _detector.Analyze([evt]).ToList();

        Assert.Single(findings);
        Assert.Contains(findings, f => f.Title.Contains("explicit credentials", StringComparison.OrdinalIgnoreCase));
        Assert.Equal(DetectionSeverity.Low, findings[0].Severity);
    }

    [Fact]
    public void Analyze_DisabledRule_ReturnsNothing()
    {
        var detector = new SuccessfulLogonDetector(Options.Create(new DetectionRulesOptions
        {
            SuccessfulLogon = new SuccessfulLogonOptions { Enabled = false }
        }));
        var events = new[]
        {
            _parser.Parse(EventXmlFixtures.SuccessfulLogon(
                "2026-08-01T12:00:00.0000000Z", "labuser", "10.0.0.50", logonType: 3)),
            _parser.Parse(EventXmlFixtures.SecurityEvent(
                4648,
                "2026-08-01T12:01:00.0000000Z",
                "LAB-HOST-01",
                ("TargetUserName", "labadmin"),
                ("SubjectUserName", "labuser")))
        };

        Assert.Empty(detector.Analyze(events));
    }
}
