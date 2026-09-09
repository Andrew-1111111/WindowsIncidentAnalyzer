using Microsoft.Extensions.Options;
using WindowsIncidentAnalyzer.Configuration;
using WindowsIncidentAnalyzer.Detectors;
using WindowsIncidentAnalyzer.Models;
using WindowsIncidentAnalyzer.Services;
using WindowsIncidentAnalyzer.Tests.Fixtures;
using Xunit;

namespace WindowsIncidentAnalyzer.Tests.UnitTests;

public sealed class ScheduledTaskDetectorTests
{
    private readonly EventXmlParser _parser = new();
    private readonly ScheduledTaskDetector _detector = new(Options.Create(new DetectionRulesOptions
    {
        SuspiciousScheduledTask = new SuspiciousScheduledTaskOptions { Enabled = true }
    }));

    [Theory]
    [InlineData(4698, "created")]
    [InlineData(4702, "updated")]
    [InlineData(4699, "deleted")]
    public void Analyze_TaskLifecycleEvents_ReportMedium(int eventId, string action)
    {
        var evt = _parser.Parse(EventXmlFixtures.SecurityEvent(
            eventId,
            "2026-08-01T14:00:00.0000000Z",
            "LAB-HOST-01",
            ("SubjectUserName", "labuser"),
            ("TaskName", @"\Maintenance\DailyBackup"),
            ("TaskContent", @"<Command>C:\Windows\System32\backup.exe</Command>")));

        var findings = _detector.Analyze([evt]).ToList();

        Assert.Single(findings);
        Assert.Contains(findings, f => f.Title.Contains($"Scheduled task {action}", StringComparison.OrdinalIgnoreCase));
        Assert.Equal(DetectionSeverity.Medium, findings[0].Severity);
    }

    [Fact]
    public void Analyze_SuspiciousTaskXml_ReportsHigh()
    {
        var evt = _parser.Parse(EventXmlFixtures.SecurityEvent(
            4698,
            "2026-08-01T14:00:00.0000000Z",
            "LAB-HOST-01",
            ("SubjectUserName", "labuser"),
            ("TaskName", @"\LabTask"),
            ("TaskContent", @"<Command>C:\Temp\agent.exe</Command>")));

        var findings = _detector.Analyze([evt]).ToList();

        Assert.Single(findings);
        Assert.Equal(DetectionSeverity.High, findings[0].Severity);
        Assert.Contains(findings, f => f.Description.Contains("suspicious path", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Analyze_DisabledRule_ReturnsNothing()
    {
        var detector = new ScheduledTaskDetector(Options.Create(new DetectionRulesOptions
        {
            SuspiciousScheduledTask = new SuspiciousScheduledTaskOptions { Enabled = false }
        }));
        var evt = _parser.Parse(EventXmlFixtures.SecurityEvent(
            4698,
            "2026-08-01T14:00:00.0000000Z",
            "LAB-HOST-01",
            ("SubjectUserName", "labuser"),
            ("TaskName", @"\LabTask"),
            ("TaskContent", @"<Command>C:\Temp\agent.exe</Command>")));

        Assert.Empty(detector.Analyze([evt]));
    }
}
