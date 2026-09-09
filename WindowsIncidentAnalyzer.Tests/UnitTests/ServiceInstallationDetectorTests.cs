using Microsoft.Extensions.Options;
using WindowsIncidentAnalyzer.Configuration;
using WindowsIncidentAnalyzer.Detectors;
using WindowsIncidentAnalyzer.Models;
using WindowsIncidentAnalyzer.Services;
using WindowsIncidentAnalyzer.Tests.Fixtures;
using Xunit;

namespace WindowsIncidentAnalyzer.Tests.UnitTests;

public sealed class ServiceInstallationDetectorTests
{
    private readonly EventXmlParser _parser = new();
    private readonly ServiceInstallationDetector _detector = new(Options.Create(new DetectionRulesOptions
    {
        ServiceInstallation = new ServiceInstallationOptions { Enabled = true }
    }));

    [Fact]
    public void Analyze_Security4697_ReportsServiceInstalled()
    {
        var evt = _parser.Parse(EventXmlFixtures.SecurityEvent(
            4697,
            "2026-08-01T16:00:00.0000000Z",
            "LAB-HOST-01",
            ("SubjectUserName", "labadmin"),
            ("ServiceName", "UpdaterSvc"),
            ("ServiceFileName", @"C:\ProgramData\updater.exe"),
            ("ServiceStartType", "3")));

        var findings = _detector.Analyze([evt]).ToList();

        Assert.Single(findings);
        Assert.Contains(findings, f => f.Title.Contains("Windows service installed", StringComparison.OrdinalIgnoreCase));
        Assert.Equal(DetectionSeverity.Medium, findings[0].Severity);
    }

    [Fact]
    public void Analyze_System7045_ReportsServiceInstalled()
    {
        var evt = _parser.Parse(EventXmlFixtures.EventlogEvent(
            7045,
            "2026-08-01T16:00:00.0000000Z",
            "LAB-HOST-01",
            ("AccountName", "labadmin"),
            ("ServiceName", "Updater"),
            ("ImagePath", @"C:\ProgramData\updater.exe")));

        var findings = _detector.Analyze([evt]).ToList();

        Assert.Single(findings);
        Assert.Contains(findings, f => f.Title.Contains("Windows service installed", StringComparison.OrdinalIgnoreCase));
        Assert.Equal(DetectionSeverity.Medium, findings[0].Severity);
    }

    [Fact]
    public void Analyze_DisabledRule_ReturnsNothing()
    {
        var detector = new ServiceInstallationDetector(Options.Create(new DetectionRulesOptions
        {
            ServiceInstallation = new ServiceInstallationOptions { Enabled = false }
        }));
        var events = new[]
        {
            _parser.Parse(EventXmlFixtures.SecurityEvent(
                4697,
                "2026-08-01T16:00:00.0000000Z",
                "LAB-HOST-01",
                ("SubjectUserName", "labadmin"),
                ("ServiceName", "UpdaterSvc"),
                ("ServiceFileName", @"C:\ProgramData\updater.exe"))),
            _parser.Parse(EventXmlFixtures.EventlogEvent(
                7045,
                "2026-08-01T16:01:00.0000000Z",
                "LAB-HOST-01",
                ("ServiceName", "Updater"),
                ("ImagePath", @"C:\ProgramData\updater.exe")))
        };

        Assert.Empty(detector.Analyze(events));
    }
}
