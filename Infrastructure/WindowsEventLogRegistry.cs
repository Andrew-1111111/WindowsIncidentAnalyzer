using Microsoft.Win32;

namespace WindowsIncidentAnalyzer.Infrastructure;

public enum EventLogChannelType
{
    Unknown = -1,
    Admin = 0,
    Operational = 1,
    Analytic = 2,
    Debug = 3
}

public readonly record struct EventLogChannelMetadata(
    EventLogChannelType Type,
    bool Enabled,
    bool IsClassic);

internal static class WindowsEventLogRegistry
{
    private const string ChannelsRoot = @"SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels";

    public static IReadOnlyList<string> EnumerateCollectibleChannelNames(bool includeAnalyticDebugLogs)
    {
        var channels = new List<string>();
        try
        {
            using var root = Registry.LocalMachine.OpenSubKey(ChannelsRoot, writable: false);
            if (root == null)
            {
                return channels;
            }

            foreach (var channelName in root.GetSubKeyNames())
            {
                if (string.IsNullOrWhiteSpace(channelName))
                {
                    continue;
                }

                if (!WindowsLogCatalog.IsCandidateChannelName(channelName, includeAnalyticDebugLogs))
                {
                    continue;
                }

                if (!TryGetChannelMetadata(channelName, out var metadata))
                {
                    continue;
                }

                if (WindowsLogCatalog.ShouldCollect(metadata, includeAnalyticDebugLogs))
                {
                    channels.Add(channelName);
                }
            }
        }
        catch
        {
            // Fall back to legacy classic logs in DiscoverLogNames.
        }

        return channels;
    }

    public static bool TryGetChannelMetadata(string channelName, out EventLogChannelMetadata metadata)
    {
        metadata = default;
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey($@"{ChannelsRoot}\{channelName}", writable: false);
            if (key == null)
            {
                return false;
            }

            metadata = new EventLogChannelMetadata(
                ReadChannelType(key),
                ReadEnabled(key),
                ReadIsClassic(key));
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static EventLogChannelType ReadChannelType(RegistryKey key)
    {
        return key.GetValue("Type") switch
        {
            int type and >= 0 and <= 3 => (EventLogChannelType)type,
            _ => EventLogChannelType.Unknown
        };
    }

    private static bool ReadEnabled(RegistryKey key) =>
        key.GetValue("Enabled") switch
        {
            int enabled => enabled != 0,
            _ => true
        };

    private static bool ReadIsClassic(RegistryKey key) =>
        key.GetValue("Classic") switch
        {
            int classic => classic != 0,
            _ => false
        };
}
