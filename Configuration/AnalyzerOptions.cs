namespace WindowsIncidentAnalyzer.Configuration;

public sealed class AnalyzerOptions
{
    /// <summary>
    /// Max concurrent workers for collect, analysis, and IOC feed downloads.
    /// 0 = unlimited; 1 = sequential; N = at most N workers.
    /// </summary>
    public int MaxDegreeOfParallelism { get; set; }

    public DatabaseOptions Database { get; set; } = new();

    public CollectionOptions Collection { get; set; } = new();

    public IocFeedOptions IocFeed { get; set; } = new();

    public HttpResilienceOptions HttpResilience { get; set; } = new();

    public StartupOptions Startup { get; set; } = new();
}

public sealed class DatabaseOptions
{
    /// <summary>
    /// Absolute path, or a relative path whose file name is stored under the app data directory
    /// (next to the exe under data/, or LocalApplicationData\WindowsIncidentAnalyzer).
    /// </summary>
    public string Path { get; set; } = "data/investigation.db";
}

public sealed class CollectionOptions
{
    public int DefaultHours { get; set; } = 24;

    public int DefaultBatchSize { get; set; } = 500;

    public int DefaultLimit { get; set; } = 100000;

    /// <summary>
    /// When true and no --log is specified, collect from every available Windows event log channel.
    /// When false, only <see cref="WindowsLogNames.DefaultCollectionLogs"/> are collected.
    /// </summary>
    public bool CollectAllLogs { get; set; } = true;

    /// <summary>
    /// When false, Analytic/Debug channels from the event log registry are excluded from collect-all.
    /// They are usually disabled and cannot be read with <see cref="EventLogReader"/>.
    /// </summary>
    public bool IncludeAnalyticDebugLogs { get; set; }

    /// <summary>
    /// Maximum seconds to wait for a single <c>EventLogReader.ReadEvent</c> call before skipping the rest of the channel.
    /// 0 disables the per-event timeout wrapper (recommended for performance).
    /// </summary>
    public int ChannelReadTimeoutSeconds { get; set; }

    /// <summary>
    /// Seconds to wait for background channel readers to stop after collection limit or cancellation is reached.
    /// </summary>
    public int ChannelShutdownTimeoutSeconds { get; set; } = 15;

    /// <summary>
    /// Retained for compatibility. Live collect always uses <c>PathType.LogName</c> (GitHub path).
    /// On-disk EVTX is only used with <c>--evtx</c>.
    /// </summary>
    public bool ReadLiveLogsFromEvtxFiles { get; set; }
}

public sealed class IocFeedOptions
{
    /// <summary>
    /// Per-feed wall-clock timeout. 0 uses <c>HttpResilience.Clients.ioc-feeds.TotalRequestTimeoutSeconds</c>.
    /// </summary>
    public int FeedDownloadTimeoutSeconds { get; set; }
}

public sealed class StartupOptions
{
    /// <summary>
    /// Download and import public IOC feeds before running commands.
    /// </summary>
    public bool AutoUpdateIocFeeds { get; set; } = true;

    /// <summary>
    /// Download Hayabusa curated rules (hayabusa-rules) before running commands.
    /// </summary>
    public bool AutoUpdateSigmaRules { get; set; } = true;

    /// <summary>
    /// Skip IOC feed download when the last successful update is newer than this many hours. 0 = always update.
    /// </summary>
    public int IocRefreshHours { get; set; } = 6;

    /// <summary>
    /// Skip Sigma download when the last successful update is newer than this many hours. 0 = always update.
    /// </summary>
    public int SigmaRefreshHours { get; set; } = 24;

    /// <summary>
    /// Download MITRE ATT&CK enterprise bundle before running commands.
    /// </summary>
    public bool AutoUpdateMitreAttack { get; set; } = true;

    /// <summary>
    /// Download CISA Known Exploited Vulnerabilities catalog before running commands.
    /// </summary>
    public bool AutoUpdateCveDatabase { get; set; } = true;

    /// <summary>
    /// Skip MITRE ATT&CK download when the last successful update is newer than this many hours. 0 = always update.
    /// </summary>
    public int MitreRefreshHours { get; set; } = 168;

    /// <summary>
    /// Skip CVE catalog download when the last successful update is newer than this many hours. 0 = always update.
    /// </summary>
    public int CveRefreshHours { get; set; } = 168;
}
