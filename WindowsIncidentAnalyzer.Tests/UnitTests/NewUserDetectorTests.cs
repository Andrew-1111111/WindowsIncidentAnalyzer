using Microsoft.Extensions.Options;
using WindowsIncidentAnalyzer.Configuration;
using WindowsIncidentAnalyzer.Detectors;
using WindowsIncidentAnalyzer.Models;
using WindowsIncidentAnalyzer.Services;
using WindowsIncidentAnalyzer.Tests.Fixtures;
using Xunit;

namespace WindowsIncidentAnalyzer.Tests.UnitTests;

public sealed class NewUserDetectorTests
{
    private readonly EventXmlParser _parser = new();
    private readonly NewUserDetector _detector = new(Options.Create(new DetectionRulesOptions
    {
        NewUser = new NewUserOptions
        {
            Enabled = true,
            PrivilegeWindowMinutes = 10
        }
    }));

    [Fact]
    public void Analyze_UserCreation4720Alone_ReportsMedium()
    {
        var evt = _parser.Parse(EventXmlFixtures.SecurityEvent(
            4720,
            "2026-08-01T13:00:00.0000000Z",
            "LAB-HOST-01",
            ("SubjectUserName", "helpdesk"),
            ("SubjectDomainName", "LAB"),
            ("TargetUserName", "tempuser"),
            ("TargetDomainName", "LAB")));

        var findings = _detector.Analyze([evt]).ToList();

        Assert.Single(findings);
        Assert.Contains(findings, f => f.Title.Contains("New user account created", StringComparison.OrdinalIgnoreCase));
        Assert.Equal(DetectionSeverity.Medium, findings[0].Severity);
    }

    [Fact]
    public void Analyze_UserCreationWithPrivilegedGroup_ReportsHigh()
    {
        var events = new[]
        {
            _parser.Parse(EventXmlFixtures.SecurityEvent(
                4720,
                "2026-08-01T13:00:00.0000000Z",
                "LAB-HOST-01",
                ("SubjectUserName", "helpdesk"),
                ("SubjectDomainName", "LAB"),
                ("TargetUserName", "tempadmin"),
                ("TargetDomainName", "LAB"))),
            _parser.Parse(EventXmlFixtures.SecurityEvent(
                4732,
                "2026-08-01T13:01:00.0000000Z",
                "LAB-HOST-01",
                ("SubjectUserName", "helpdesk"),
                ("TargetUserName", "Administrators"),
                ("MemberName", @"LAB\tempadmin")))
        };

        var findings = _detector.Analyze(events).ToList();

        Assert.Single(findings);
        Assert.Contains(findings, f => f.Title.Contains("privileged group", StringComparison.OrdinalIgnoreCase));
        Assert.Equal(DetectionSeverity.High, findings[0].Severity);
    }

    [Fact]
    public void Analyze_DisabledRule_ReturnsNothing()
    {
        var detector = new NewUserDetector(Options.Create(new DetectionRulesOptions
        {
            NewUser = new NewUserOptions { Enabled = false }
        }));
        var evt = _parser.Parse(EventXmlFixtures.SecurityEvent(
            4720,
            "2026-08-01T13:00:00.0000000Z",
            "LAB-HOST-01",
            ("SubjectUserName", "helpdesk"),
            ("TargetUserName", "tempuser")));

        Assert.Empty(detector.Analyze([evt]));
    }
}
