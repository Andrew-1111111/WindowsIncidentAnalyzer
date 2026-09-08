namespace WindowsIncidentAnalyzer.Infrastructure;

/// <summary>
/// Discovers and resolves on-disk Windows event log files (Hayabusa-style live analysis).
/// Live collection reads <c>%WINDIR%\System32\winevt\Logs\*.evtx</c> instead of opening channels by name.
/// </summary>
public static class WindowsEvtxLogCatalog
{
    public static string LiveLogsDirectory =>
        Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.Windows),
            "System32",
            "winevt",
            "Logs");

    public static string ChannelNameToEvtxFileName(string channelName) =>
        $"{EncodeChannelName(channelName)}.evtx";

    public static string EvtxFileNameToChannelName(string fileName)
    {
        var stem = Path.GetFileNameWithoutExtension(fileName);
        return DecodeChannelName(stem);
    }

    public static string ResolveEvtxPath(string channelName) =>
        Path.Combine(LiveLogsDirectory, ChannelNameToEvtxFileName(channelName));

    public static bool TryResolveEvtxPath(string channelName, out string evtxPath)
    {
        evtxPath = ResolveEvtxPath(channelName);
        return File.Exists(evtxPath);
    }

    public static bool IsReadableEvtxFile(string evtxPath)
    {
        if (!File.Exists(evtxPath))
        {
            return false;
        }

        try
        {
            return new FileInfo(evtxPath).Length >= 4096;
        }
        catch
        {
            return false;
        }
    }

    public static IReadOnlyList<string> DiscoverEvtxFilePaths(bool includeAnalyticDebugLogs = false)
    {
        if (!Directory.Exists(LiveLogsDirectory))
        {
            return [];
        }

        try
        {
            return Directory.EnumerateFiles(LiveLogsDirectory, "*.evtx", SearchOption.TopDirectoryOnly)
                .Where(path => IsReadableEvtxFile(path))
                .Where(path => IsCollectibleEvtxFile(path, includeAnalyticDebugLogs))
                .OrderBy(static path => path, StringComparer.OrdinalIgnoreCase)
                .ToList();
        }
        catch
        {
            return [];
        }
    }

    public static IReadOnlyList<string> DiscoverChannelNames(bool includeAnalyticDebugLogs = false) =>
        DiscoverEvtxFilePaths(includeAnalyticDebugLogs)
            .Select(static path => EvtxFileNameToChannelName(Path.GetFileName(path)))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(static name => name, StringComparer.OrdinalIgnoreCase)
            .ToList();

    public static bool IsCollectibleEvtxFile(string evtxPath, bool includeAnalyticDebugLogs)
    {
        if (!File.Exists(evtxPath))
        {
            return false;
        }

        var channelName = EvtxFileNameToChannelName(Path.GetFileName(evtxPath));
        return WindowsLogCatalog.IsCandidateChannelName(channelName, includeAnalyticDebugLogs);
    }

    internal static string EncodeChannelName(string channelName) =>
        channelName.Replace("/", "%4", StringComparison.Ordinal);

    internal static string DecodeChannelName(string encodedChannelName) =>
        encodedChannelName.Replace("%4", "/", StringComparison.Ordinal);
}
