using WindowsIncidentAnalyzer.Infrastructure;
using Xunit;

namespace WindowsIncidentAnalyzer.Tests.UnitTests;

public sealed class WindowsLogCatalogTests
{
    [Theory]
    [InlineData("all", true)]
    [InlineData("ALL", true)]
    [InlineData("*", true)]
    [InlineData("all-logs", true)]
    [InlineData("Security", false)]
    [InlineData("", false)]
    public void IsAllLogsAlias_RecognizesAliases(string value, bool expected) =>
        Assert.Equal(expected, WindowsLogCatalog.IsAllLogsAlias(value));

    [Fact]
    public void ResolveCollectionLogs_WithExplicitLog_ReturnsSingleChannel()
    {
        var logs = WindowsLogCatalog.ResolveCollectionLogs("Security", collectAllLogs: true);

        Assert.Single(logs);
        Assert.Equal(WindowsLogNames.Security, logs[0]);
    }

    [Fact]
    public void ResolveCollectionLogs_WhenCollectAllDisabled_ReturnsCollectibleDefaultSet()
    {
        var logs = WindowsLogCatalog.ResolveCollectionLogs(null, collectAllLogs: false);

        Assert.NotEmpty(logs);
        Assert.Contains(WindowsLogNames.Security, logs, StringComparer.OrdinalIgnoreCase);
        Assert.Contains(WindowsLogNames.System, logs, StringComparer.OrdinalIgnoreCase);
        Assert.Contains(WindowsLogNames.Application, logs, StringComparer.OrdinalIgnoreCase);
        // Optional channels (Sysmon) are omitted when not installed — avoids EventLogNotFoundException.
        Assert.All(logs, name => Assert.True(WindowsLogCatalog.IsPresentChannel(name)));
    }

    [Fact]
    public void IsPresentChannel_ClassicLogsAreAlwaysPresent()
    {
        Assert.True(WindowsLogCatalog.IsPresentChannel(WindowsLogNames.Security));
        Assert.True(WindowsLogCatalog.IsPresentChannel(WindowsLogNames.System));
        Assert.True(WindowsLogCatalog.IsPresentChannel(WindowsLogNames.Application));
    }

    [Theory]
    [InlineData("Microsoft-Windows-PowerShell/Operational", true)]
    [InlineData("Microsoft-Windows-Kernel-EventTracing/Analytic", false)]
    [InlineData("Microsoft-Windows-Sysmon/Operational/Debug", false)]
    [InlineData("Microsoft-Windows-Kernel-EventTracing/Analytic", true, true)]
    public void IsCandidateChannelName_FiltersAnalyticAndDebugByDefault(
        string logName,
        bool expected,
        bool includeAnalyticDebug = false) =>
        Assert.Equal(expected, WindowsLogCatalog.IsCandidateChannelName(logName, includeAnalyticDebug));

    [Theory]
    [InlineData(EventLogChannelType.Operational, true, false, true)]
    [InlineData(EventLogChannelType.Analytic, true, false, false)]
    [InlineData(EventLogChannelType.Debug, true, false, false)]
    [InlineData(EventLogChannelType.Analytic, true, true, true)]
    [InlineData(EventLogChannelType.Operational, false, false, false)]
    public void ShouldCollect_UsesRegistryMetadata(
        EventLogChannelType type,
        bool enabled,
        bool includeAnalyticDebug,
        bool expected) =>
        Assert.Equal(
            expected,
            WindowsLogCatalog.ShouldCollect(
                new EventLogChannelMetadata(type, enabled, IsClassic: false),
                includeAnalyticDebug));

    [Fact]
    public void DiscoverLogNames_ReturnsAtLeastDefaultChannelsOnWindows()
    {
        var logs = WindowsLogCatalog.DiscoverLogNames(discoverFromEvtxFiles: false);

        Assert.NotEmpty(logs);
        Assert.Contains(WindowsLogNames.Security, logs, StringComparer.OrdinalIgnoreCase);
        Assert.Contains(WindowsLogNames.System, logs, StringComparer.OrdinalIgnoreCase);
    }

    [Fact]
    public void DiscoverLogNames_RegistryMode_ListsOpenableLogNameChannels()
    {
        var logs = WindowsLogCatalog.DiscoverLogNames(discoverFromEvtxFiles: false);
        Assert.True(logs.Count >= 3, $"Expected registry-backed channel list, got {logs.Count}.");

        var failures = new List<string>();
        var probed = 0;

        foreach (var channel in logs.Take(25))
        {
            probed++;
            try
            {
                using var reader = new System.Diagnostics.Eventing.Reader.EventLogReader(
                    new System.Diagnostics.Eventing.Reader.EventLogQuery(
                        channel,
                        System.Diagnostics.Eventing.Reader.PathType.LogName));
            }
            catch (System.Diagnostics.Eventing.Reader.EventLogNotFoundException)
            {
                // Optional / removed channels are skipped at collect time.
            }
            catch (UnauthorizedAccessException)
            {
                // Security without elevation is expected in some test hosts.
            }
            catch (System.Exception ex)
            {
                failures.Add($"{channel}: {ex.GetType().Name}");
            }
        }

        Assert.True(
            failures.Count == 0,
            $"Unexpected open failures ({failures.Count}/{probed}): {string.Join(", ", failures)}");
    }
}
