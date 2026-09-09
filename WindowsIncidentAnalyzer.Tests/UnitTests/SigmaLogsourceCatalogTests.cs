using WindowsIncidentAnalyzer.Models;
using WindowsIncidentAnalyzer.Sigma;
using WindowsIncidentAnalyzer.Sigma.Models;
using Xunit;

namespace WindowsIncidentAnalyzer.Tests.UnitTests;

public sealed class SigmaLogsourceCatalogTests
{
    [Theory]
    [InlineData("process_creation", 1, 4688)]
    [InlineData("ps_script", 4103, 4104)]
    [InlineData("network_connection", 3)]
    [InlineData("authentication", 4624, 4625, 4648, 4771, 4776)]
    public void ResolveEventIds_ReturnsCategoryEventIds(string category, params int[] expected)
    {
        var ids = SigmaLogsourceCatalog.ResolveEventIds(new SigmaLogsource
        {
            Category = category
        });

        Assert.Equal(expected.OrderBy(x => x), ids.OrderBy(x => x));
    }

    [Fact]
    public void ResolveEventIds_UnknownCategory_ReturnsEmpty()
    {
        var ids = SigmaLogsourceCatalog.ResolveEventIds(new SigmaLogsource
        {
            Category = "custom_behavior"
        });

        Assert.Empty(ids);
    }

    [Fact]
    public void MatchesEvent_SecurityChannel_EnglishAndRussian()
    {
        var rule = CreateRule(service: "security", category: "authentication");

        var english = CreateEvent(4624, logName: "Security", provider: "Microsoft-Windows-Security-Auditing");
        var russian = CreateEvent(4624, logName: "Безопасность", provider: "Microsoft-Windows-Security-Auditing");

        Assert.True(SigmaLogsourceCatalog.MatchesEvent(rule, english));
        Assert.True(SigmaLogsourceCatalog.MatchesEvent(rule, russian));
    }

    [Fact]
    public void MatchesEvent_PowerShellService_RequiresPowerShellChannelOrProvider()
    {
        var rule = CreateRule(service: "powershell", category: "ps_script");

        var match = CreateEvent(
            4104,
            logName: "Microsoft-Windows-PowerShell/Operational",
            provider: "Microsoft-Windows-PowerShell");

        var wrongProvider = CreateEvent(
            4104,
            logName: "Application",
            provider: "Some-Other-Provider");

        Assert.True(SigmaLogsourceCatalog.MatchesEvent(rule, match));
        Assert.False(SigmaLogsourceCatalog.MatchesEvent(rule, wrongProvider));
    }

    [Fact]
    public void MatchesEvent_SysmonService_AcceptsSysmonChannelOrProvider()
    {
        var rule = CreateRule(service: "sysmon", category: "process_creation");

        var channelMatch = CreateEvent(
            1,
            logName: "Microsoft-Windows-Sysmon/Operational",
            provider: "Microsoft-Windows-Sysmon");

        var providerOnly = CreateEvent(
            1,
            logName: "ForwardedEvents",
            provider: "Microsoft-Windows-Sysmon");

        var nonSysmon = CreateEvent(
            1,
            logName: "Security",
            provider: "Microsoft-Windows-Security-Auditing");

        Assert.True(SigmaLogsourceCatalog.MatchesEvent(rule, channelMatch));
        Assert.True(SigmaLogsourceCatalog.MatchesEvent(rule, providerOnly));
        Assert.False(SigmaLogsourceCatalog.MatchesEvent(rule, nonSysmon));
    }

    [Fact]
    public void MatchesEvent_NonWindowsProduct_ReturnsFalse()
    {
        var rule = CreateRule(product: "linux", service: "security", category: "authentication");
        var evt = CreateEvent(4624, logName: "Security");

        Assert.False(SigmaLogsourceCatalog.MatchesEvent(rule, evt));
    }

    [Fact]
    public void MatchesEvent_CategoryMismatch_ReturnsFalse()
    {
        var rule = CreateRule(category: "network_connection");
        var evt = CreateEvent(4688, logName: "Security", provider: "Microsoft-Windows-Security-Auditing");

        Assert.False(SigmaLogsourceCatalog.MatchesEvent(rule, evt));
    }

    [Fact]
    public void CategoryMatchesEvent_SysmonEventIdWithoutSysmonProvider_ReturnsFalse()
    {
        var evt = CreateEvent(3, logName: "Security", provider: "Microsoft-Windows-Security-Auditing");

        Assert.False(SigmaLogsourceCatalog.CategoryMatchesEvent(evt, "network_connection"));
    }

    [Fact]
    public void CategoryMatchesEvent_Event104RequiresEventlogProvider()
    {
        var valid = CreateEvent(104, provider: "Microsoft-Windows-Eventlog");
        var invalid = CreateEvent(104, provider: "Other-Provider");

        Assert.True(SigmaLogsourceCatalog.CategoryMatchesEvent(valid, "log_clearing"));
        Assert.False(SigmaLogsourceCatalog.CategoryMatchesEvent(invalid, "log_clearing"));
    }

    [Fact]
    public void ClassifyEvent_ReturnsBestMatchingCategory()
    {
        var evt = CreateEvent(
            4104,
            logName: "Microsoft-Windows-PowerShell/Operational",
            provider: "Microsoft-Windows-PowerShell");

        Assert.Equal("ps_script", SigmaLogsourceCatalog.ClassifyEvent(evt));
    }

    [Fact]
    public void AggregateEventIds_CollectsDistinctIdsFromRules()
    {
        var rules = new[]
        {
            new SigmaRule
            {
                RelevantEventIds = [1, 4688]
            },
            new SigmaRule
            {
                RelevantEventIds = [4688, 4104]
            }
        };

        var ids = SigmaLogsourceCatalog.AggregateEventIds(rules);

        Assert.Equal([1, 4104, 4688], ids);
    }

    private static SigmaRule CreateRule(
        string product = "windows",
        string? service = null,
        string? category = null) =>
        new()
        {
            Logsource = new SigmaLogsource
            {
                Product = product,
                Service = service,
                Category = category
            }
        };

    private static WindowsEvent CreateEvent(
        int eventId,
        string? logName = null,
        string? provider = null) =>
        new()
        {
            EventId = eventId,
            LogName = logName,
            ProviderName = provider,
            TimeCreatedUtc = DateTime.UtcNow
        };
}
