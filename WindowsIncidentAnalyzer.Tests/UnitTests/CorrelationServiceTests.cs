using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using WindowsIncidentAnalyzer.Configuration;
using WindowsIncidentAnalyzer.Models;
using WindowsIncidentAnalyzer.Services;
using WindowsIncidentAnalyzer.Tests.Fixtures;
using Xunit;

namespace WindowsIncidentAnalyzer.Tests.UnitTests;

public sealed class CorrelationServiceTests
{
    private readonly EventXmlParser _parser = new();

    private CorrelationService CreateService() =>
        new(null!, Options.Create(new DetectionRulesOptions
        {
            Correlation = new CorrelationOptions { CorrelationWindowMinutes = 10 }
        }), Options.Create(new AnalyzerOptions()), NullLogger<CorrelationService>.Instance);

    [Fact]
    public void Correlate_FailedThenSuccessThen4672_IsPrivilegedCompromise()
    {
        var start = new DateTime(2026, 8, 1, 12, 0, 0, DateTimeKind.Utc);
        var events = Enumerable.Range(0, 5)
            .Select(i => _parser.Parse(EventXmlFixtures.FailedLogon(start.AddSeconds(i).ToString("o"), "labadmin", "10.0.0.9")))
            .ToList();
        events.Add(_parser.Parse(EventXmlFixtures.SuccessfulLogon(start.AddMinutes(1).ToString("o"), "labadmin", "10.0.0.9")));
        events.Add(_parser.Parse(EventXmlFixtures.SpecialPrivileges(start.AddMinutes(1).AddSeconds(2).ToString("o"), "labadmin")));

        var chains = CreateService().Correlate(events);
        Assert.Contains(chains, c => c.Title.Contains("compromised privileged account", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Correlate_NewUserGroupThenLogon_IsSuspiciousCreation()
    {
        var t0 = "2026-08-01T13:00:00.0000000Z";
        var t1 = "2026-08-01T13:01:00.0000000Z";
        var t2 = "2026-08-01T13:02:00.0000000Z";
        var events = new List<WindowsEvent>
        {
            _parser.Parse(EventXmlFixtures.SecurityEvent(4720, t0, "LAB-HOST-01",
                ("SubjectUserName", "helpdesk"),
                ("SubjectDomainName", "LAB"),
                ("TargetUserName", "tempadmin"),
                ("TargetDomainName", "LAB"))),
            _parser.Parse(EventXmlFixtures.SecurityEvent(4732, t1, "LAB-HOST-01",
                ("SubjectUserName", "helpdesk"),
                ("TargetUserName", "Administrators"),
                ("MemberName", @"LAB\tempadmin"))),
            _parser.Parse(EventXmlFixtures.SuccessfulLogon(t2, "tempadmin", "10.0.0.20", 2))
        };

        var chains = CreateService().Correlate(events);
        Assert.Contains(chains, c => c.Title.Contains("account creation", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Correlate_ScheduledTaskThenMatchingProcess_IsPersistence()
    {
        var events = new List<WindowsEvent>
        {
            _parser.Parse(EventXmlFixtures.SecurityEvent(4698, "2026-08-01T14:00:00.0000000Z", "LAB-HOST-01",
                ("SubjectUserName", "labuser"),
                ("TaskName", @"\\LabTask"),
                ("TaskContent", @"<Command>C:\Temp\agent.exe</Command>"))),
            _parser.Parse(EventXmlFixtures.SecurityEvent(4688, "2026-08-01T14:01:00.0000000Z", "LAB-HOST-01",
                ("SubjectUserName", "labuser"),
                ("NewProcessName", @"C:\Temp\agent.exe"),
                ("NewProcessId", "4000"),
                ("ProcessId", "1000"),
                ("CommandLine", @"C:\Temp\agent.exe")))
        };

        var chains = CreateService().Correlate(events);
        Assert.Contains(chains, c => c.Title.Contains("persistence", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Correlate_RemoteLogonThenPowerShell_IsSuspiciousExecution()
    {
        var start = new DateTime(2026, 8, 1, 15, 0, 0, DateTimeKind.Utc);
        var events = new List<WindowsEvent>
        {
            _parser.Parse(EventXmlFixtures.SuccessfulLogon(start.ToString("o"), "labuser", "10.0.0.55", 10)),
            new()
            {
                EventId = 4688,
                TimeCreatedUtc = start.AddMinutes(1),
                ComputerName = "LAB-HOST-01",
                User = "labuser",
                ProcessName = "powershell.exe",
                ProcessPath = @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                CommandLine = "powershell.exe -NoProfile"
            }
        };

        var chains = CreateService().Correlate(events);
        Assert.Contains(chains, c => c.Scenario == "RemoteLogonThenSuspiciousProcess");
    }

    [Fact]
    public void Correlate_ServiceInstallThenImageExecution_IsServicePersistence()
    {
        var start = new DateTime(2026, 8, 1, 16, 0, 0, DateTimeKind.Utc);
        var events = new List<WindowsEvent>
        {
            new()
            {
                EventId = 7045,
                TimeCreatedUtc = start,
                ComputerName = "LAB-HOST-01",
                User = "labadmin",
                ServiceName = "Updater",
                ProcessPath = @"C:\ProgramData\updater.exe"
            },
            new()
            {
                EventId = 4688,
                TimeCreatedUtc = start.AddSeconds(30),
                ComputerName = "LAB-HOST-01",
                User = "SYSTEM",
                ProcessName = "updater.exe",
                ProcessPath = @"C:\ProgramData\updater.exe"
            }
        };

        var chains = CreateService().Correlate(events);
        Assert.Contains(chains, c => c.Scenario == "ServiceInstalledThenProcess");
    }
}
