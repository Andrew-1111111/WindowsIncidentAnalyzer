using System.Collections.Concurrent;

namespace WindowsIncidentAnalyzer.Infrastructure;

public static class WindowsLogCatalog
{
    private static readonly HashSet<string> LegacyClassicLogs = new(StringComparer.OrdinalIgnoreCase)
    {
        WindowsLogNames.Security,
        WindowsLogNames.System,
        WindowsLogNames.Application
    };

    private static readonly ConcurrentDictionary<string, byte> KnownMissingChannels = new(StringComparer.OrdinalIgnoreCase);

    public static bool IsAllLogsAlias(string? value) =>
        !string.IsNullOrWhiteSpace(value) && (
            value.Equals("all", StringComparison.OrdinalIgnoreCase) ||
            value.Equals("*", StringComparison.Ordinal) ||
            value.Equals("all-logs", StringComparison.OrdinalIgnoreCase));

    public static IReadOnlyList<string> ResolveCollectionLogs(
        string? logName,
        bool collectAllLogs,
        bool includeAnalyticDebugLogs = false,
        bool discoverFromEvtxFiles = false)
    {
        if (!string.IsNullOrWhiteSpace(logName))
        {
            if (IsAllLogsAlias(logName))
            {
                return DiscoverLogNames(includeAnalyticDebugLogs, discoverFromEvtxFiles);
            }

            return [WindowsLogNames.Resolve(logName)];
        }

        return collectAllLogs
            ? DiscoverLogNames(includeAnalyticDebugLogs, discoverFromEvtxFiles)
            : GetDefaultCollectionLogs(includeAnalyticDebugLogs, discoverFromEvtxFiles);
    }

    public static IReadOnlyList<string> GetDefaultCollectionLogs(
        bool includeAnalyticDebugLogs = false,
        bool discoverFromEvtxFiles = false)
    {
        // Match GitHub's default set, but skip channels that are not installed (e.g. Sysmon)
        // so EventLogReader never throws EventLogNotFoundException first-chance in the debugger.
        if (discoverFromEvtxFiles)
        {
            var available = WindowsLogNames.DefaultCollectionLogs
                .Where(log => WindowsEvtxLogCatalog.TryResolveEvtxPath(log, out _))
                .ToList();
            if (available.Count > 0)
            {
                return available;
            }
        }

        return WindowsLogNames.DefaultCollectionLogs
            .Where(IsPresentChannel)
            .ToList();
    }

    /// <summary>
    /// True when the channel is a classic log or registered under WINEVT\Channels
    /// (avoids opening missing optional channels such as Sysmon).
    /// </summary>
    public static bool IsPresentChannel(string logName)
    {
        if (string.IsNullOrWhiteSpace(logName))
        {
            return false;
        }

        if (LegacyClassicLogs.Contains(logName))
        {
            return true;
        }

        return WindowsEventLogRegistry.TryGetChannelMetadata(logName, out _);
    }

    public static IReadOnlyList<string> DiscoverLogNames(
        bool includeAnalyticDebugLogs = false,
        bool discoverFromEvtxFiles = false)
    {
        // Prefer registry-enabled channels (stable). EVTX disk walk is opt-in and still
        // filtered to enabled/classic channels to avoid opening hundreds of dead placeholders.
        if (discoverFromEvtxFiles)
        {
            var fromEvtx = WindowsEvtxLogCatalog.DiscoverChannelNames(includeAnalyticDebugLogs)
                .Where(name => IsCollectibleChannel(name, includeAnalyticDebugLogs) ||
                               LegacyClassicLogs.Contains(name))
                .ToList();
            if (fromEvtx.Count > 0)
            {
                return fromEvtx;
            }
        }

        try
        {
            var names = WindowsEventLogRegistry.EnumerateCollectibleChannelNames(includeAnalyticDebugLogs)
                .Where(name => !IsKnownMissingChannel(name))
                .ToList();

            AppendLegacyClassicLogs(names);

            return names.Count > 0
                ? names.OrderBy(static name => name, StringComparer.OrdinalIgnoreCase).ToList()
                : GetDefaultCollectionLogs(includeAnalyticDebugLogs, discoverFromEvtxFiles: false);
        }
        catch
        {
            return GetDefaultCollectionLogs(includeAnalyticDebugLogs, discoverFromEvtxFiles: false);
        }
    }

    private static void AppendLegacyClassicLogs(ICollection<string> names)
    {
        foreach (var classic in LegacyClassicLogs)
        {
            if (!names.Contains(classic, StringComparer.OrdinalIgnoreCase))
            {
                names.Add(classic);
            }
        }
    }

    public static bool IsKnownMissingChannel(string logName) =>
        KnownMissingChannels.ContainsKey(logName);

    public static void MarkMissingChannel(string logName) =>
        KnownMissingChannels.TryAdd(logName, 0);

    public static bool IsCandidateChannelName(string logName, bool includeAnalyticDebugLogs)
    {
        if (includeAnalyticDebugLogs)
        {
            return true;
        }

        return !logName.EndsWith("/Analytic", StringComparison.OrdinalIgnoreCase) &&
               !logName.EndsWith("/Debug", StringComparison.OrdinalIgnoreCase);
    }

    public static bool IsCollectibleChannel(string logName, bool includeAnalyticDebugLogs)
    {
        if (!IsCandidateChannelName(logName, includeAnalyticDebugLogs))
        {
            return false;
        }

        if (KnownMissingChannels.ContainsKey(logName))
        {
            return false;
        }

        if (WindowsEventLogRegistry.TryGetChannelMetadata(logName, out var metadata))
        {
            return ShouldCollect(metadata, includeAnalyticDebugLogs);
        }

        if (LegacyClassicLogs.Contains(logName))
        {
            return true;
        }

        return false;
    }

    public static bool ShouldCollect(EventLogChannelMetadata metadata, bool includeAnalyticDebugLogs)
    {
        if (!includeAnalyticDebugLogs &&
            metadata.Type is EventLogChannelType.Analytic or EventLogChannelType.Debug)
        {
            return false;
        }

        return metadata.Enabled;
    }
}
