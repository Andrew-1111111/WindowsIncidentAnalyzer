using Microsoft.Extensions.Options;
using WindowsIncidentAnalyzer.Configuration;
using WindowsIncidentAnalyzer.Detectors;
using WindowsIncidentAnalyzer.Models;
using WindowsIncidentAnalyzer.Services;
using WindowsIncidentAnalyzer.Tests.Fixtures;
using Xunit;

namespace WindowsIncidentAnalyzer.Tests.UnitTests;

public sealed class ProcessCreationDetectorTests
{
    private readonly EventXmlParser _parser = new();
    private readonly ProcessCreationDetector _detector = new(Options.Create(new DetectionRulesOptions
    {
        SuspiciousProcessCreation = new SuspiciousProcessCreationOptions
        {
            Enabled = true,
            LongCommandLineLength = 500
        }
    }));

    [Fact]
    public void Analyze_SuspiciousProcessPath_ReportsMedium()
    {
        var evt = _parser.Parse(EventXmlFixtures.SecurityEvent(
            4688,
            "2026-08-01T08:00:00.0000000Z",
            "LAB-HOST-01",
            ("SubjectUserName", "labuser"),
            ("NewProcessName", @"C:\Users\labuser\Downloads\payload.exe"),
            ("NewProcessId", "0x1a2"),
            ("ProcessId", "0x3e8"),
            ("CommandLine", @"C:\Users\labuser\Downloads\payload.exe"),
            ("ParentProcessName", @"C:\Windows\explorer.exe")));

        var findings = _detector.Analyze([evt]).ToList();

        Assert.Single(findings);
        Assert.Contains(findings, f => f.Title.Contains("Suspicious process creation", StringComparison.OrdinalIgnoreCase));
        Assert.Equal(DetectionSeverity.Medium, findings[0].Severity);
    }

    [Fact]
    public void Analyze_LongCommandLine_ReportsMedium()
    {
        var longCmd = new string('A', 500);
        var evt = _parser.Parse(EventXmlFixtures.SecurityEvent(
            4688,
            "2026-08-01T08:00:00.0000000Z",
            "LAB-HOST-01",
            ("SubjectUserName", "labuser"),
            ("NewProcessName", @"C:\Windows\System32\cmd.exe"),
            ("NewProcessId", "0x1a2"),
            ("ProcessId", "0x3e8"),
            ("CommandLine", longCmd),
            ("ParentProcessName", @"C:\Windows\explorer.exe")));

        var findings = _detector.Analyze([evt]).ToList();

        Assert.Single(findings);
        Assert.Contains(findings, f => f.Description.Contains("command line length", StringComparison.OrdinalIgnoreCase));
        Assert.Equal(DetectionSeverity.Medium, findings[0].Severity);
    }

    [Fact]
    public void Analyze_SuspiciousParentChild_ReportsMedium()
    {
        var evt = _parser.Parse(EventXmlFixtures.SecurityEvent(
            4688,
            "2026-08-01T08:00:00.0000000Z",
            "LAB-HOST-01",
            ("SubjectUserName", "labuser"),
            ("NewProcessName", @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"),
            ("NewProcessId", "0x1a2"),
            ("ProcessId", "0x3e8"),
            ("CommandLine", "powershell.exe -NoProfile"),
            ("ParentProcessName", @"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE")));

        var findings = _detector.Analyze([evt]).ToList();

        Assert.Single(findings);
        Assert.Contains(findings, f => f.Description.Contains("winword.exe -> powershell.exe", StringComparison.OrdinalIgnoreCase));
        Assert.Equal(DetectionSeverity.Medium, findings[0].Severity);
    }

    [Fact]
    public void Analyze_SysmonEventId1_ReportsFinding()
    {
        var evt = _parser.Parse(EventXmlFixtures.SysmonEvent(
            1,
            "2026-08-01T08:00:00.0000000Z",
            "LAB-HOST-01",
            ("Image", @"C:\Users\labuser\AppData\Local\Temp\agent.exe"),
            ("CommandLine", @"C:\Users\labuser\AppData\Local\Temp\agent.exe"),
            ("ProcessId", "4242"),
            ("ParentImage", @"C:\Windows\System32\services.exe"),
            ("ParentProcessId", "888"),
            ("User", @"LAB\labuser")));

        var findings = _detector.Analyze([evt]).ToList();

        Assert.Single(findings);
        Assert.Contains(findings, f => f.Title.Contains("Suspicious process creation", StringComparison.OrdinalIgnoreCase));
    }
}
