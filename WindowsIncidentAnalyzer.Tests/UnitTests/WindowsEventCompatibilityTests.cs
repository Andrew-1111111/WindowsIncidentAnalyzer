using WindowsIncidentAnalyzer.Infrastructure;
using WindowsIncidentAnalyzer.Models;
using WindowsIncidentAnalyzer.Sigma;
using WindowsIncidentAnalyzer.Sigma.Models;
using Xunit;

namespace WindowsIncidentAnalyzer.Tests.UnitTests;

public sealed class WindowsEventCompatibilityTests
{
    [Fact]
    public void ClassifyEvent_SysmonProcessCreation_ReturnsProcessCreation()
    {
        var evt = new WindowsEvent
        {
            EventId = 1,
            ProviderName = "Microsoft-Windows-Sysmon",
            LogName = "Microsoft-Windows-Sysmon/Operational"
        };

        Assert.Equal("process_creation", SigmaLogsourceCatalog.ClassifyEvent(evt));
        Assert.True(SigmaLogsourceCatalog.CategoryMatchesEvent(evt, "process_creation"));
    }

    [Fact]
    public void ClassifyEvent_NonSysmonEventId1_DoesNotMatchProcessCreation()
    {
        var evt = new WindowsEvent
        {
            EventId = 1,
            ProviderName = "Microsoft-Windows-Hyper-V-Hypervisor",
            LogName = "System"
        };

        Assert.Null(SigmaLogsourceCatalog.ClassifyEvent(evt));
        Assert.False(SigmaLogsourceCatalog.CategoryMatchesEvent(evt, "process_creation"));
    }

    [Fact]
    public void MatchesEvent_SigmaProcessCreationRule_RejectsNonSysmonEventId1()
    {
        var rule = new SigmaRule
        {
            Logsource = new SigmaLogsource { Product = "windows", Category = "process_creation" }
        };
        var evt = new WindowsEvent
        {
            EventId = 1,
            ProviderName = "Microsoft-Windows-FilterManager",
            LogName = "System"
        };

        Assert.False(SigmaLogsourceCatalog.MatchesEvent(rule, evt));
    }

    [Fact]
    public void MatchesEvent_SigmaProcessCreationRule_AcceptsSecurity4688()
    {
        var rule = new SigmaRule
        {
            Logsource = new SigmaLogsource { Product = "windows", Category = "process_creation" }
        };
        var evt = new WindowsEvent
        {
            EventId = 4688,
            ProviderName = "Microsoft-Windows-Security-Auditing",
            LogName = "Security"
        };

        Assert.True(SigmaLogsourceCatalog.MatchesEvent(rule, evt));
        Assert.Equal("process_creation", SigmaLogsourceCatalog.ClassifyEvent(evt));
    }

    [Fact]
    public void CategoryMatchesEvent_BehavioralDetectorName_AlwaysTrue()
    {
        var evt = new WindowsEvent
        {
            EventId = 4104,
            ProviderName = "Microsoft-Windows-PowerShell",
            LogName = "Microsoft-Windows-PowerShell/Operational"
        };

        Assert.True(SigmaLogsourceCatalog.CategoryMatchesEvent(evt, "DefenseEvasion"));
        Assert.Equal("ps_script", SigmaLogsourceCatalog.ClassifyEvent(evt));
    }

    [Fact]
    public void ValidateSeverity_ContentDrivenCriticalOnPowerShell_IsAllowed()
    {
        var evt = new WindowsEvent
        {
            EventId = 4104,
            ProviderName = "Microsoft-Windows-PowerShell",
            LogName = "Microsoft-Windows-PowerShell/Operational"
        };
        var context = new FindingContext { Category = "CredentialAccess" };
        WindowsEventCompatibility.ApplyEventClassification(context, evt);

        var result = WindowsEventCompatibility.ValidateSeverity(
            DetectionSeverity.Critical,
            evt,
            context,
            "CredentialAccess");

        Assert.True(result.Matches);
        Assert.Equal(DetectionSeverity.Critical, result.Severity);
    }

    [Fact]
    public void ValidateSeverity_StructuralCriticalOnChannelClear_IsCappedToHigh()
    {
        var evt = new WindowsEvent
        {
            EventId = 104,
            ProviderName = "Microsoft-Windows-Eventlog",
            LogName = "System"
        };
        var context = new FindingContext { Category = "RdpActivity" };
        WindowsEventCompatibility.ApplyEventClassification(context, evt);

        var result = WindowsEventCompatibility.ValidateSeverity(
            DetectionSeverity.Critical,
            evt,
            context,
            "RdpActivity");

        Assert.False(result.Matches);
        Assert.Equal(DetectionSeverity.High, result.Severity);
    }

    [Fact]
    public void ValidateSeverity_CriticalOnNonSysmonEventId1_IsCappedToMedium()
    {
        var evt = new WindowsEvent
        {
            EventId = 1,
            ProviderName = "Microsoft-Windows-Hyper-V-Hypervisor",
            LogName = "System"
        };
        var context = new FindingContext { Category = "SigmaRules" };
        WindowsEventCompatibility.ApplyEventClassification(context, evt);

        var result = WindowsEventCompatibility.ValidateSeverity(
            DetectionSeverity.Critical,
            evt,
            context,
            "SigmaRules");

        Assert.False(result.Matches);
        Assert.Equal(DetectionSeverity.Medium, result.Severity);
    }

    [Fact]
    public void ValidateSeverity_SecurityLogClearingCritical_IsAllowed()
    {
        var evt = new WindowsEvent
        {
            EventId = 1102,
            ProviderName = "Microsoft-Windows-Security-Auditing",
            LogName = "Security"
        };
        var context = new FindingContext { Category = "LogClearing" };
        WindowsEventCompatibility.ApplyEventClassification(context, evt);

        var result = WindowsEventCompatibility.ValidateSeverity(
            DetectionSeverity.Critical,
            evt,
            context,
            "LogClearing");

        Assert.True(result.Matches);
        Assert.Equal(DetectionSeverity.Critical, result.Severity);
    }
}
