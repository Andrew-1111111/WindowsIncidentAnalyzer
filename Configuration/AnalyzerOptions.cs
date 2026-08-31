namespace WindowsIncidentAnalyzer.Configuration;

public sealed class AnalyzerOptions
{
    public DatabaseOptions Database { get; set; } = new();

    public CollectionOptions Collection { get; set; } = new();

    public AnalysisOptions Analysis { get; set; } = new();

    public IocFeedOptions IocFeed { get; set; } = new();

    public StartupOptions Startup { get; set; } = new();
}

public sealed class DatabaseOptions
{
    public string Path { get; set; } = "data/investigation.db";
}

public sealed class CollectionOptions
{
    public int DefaultHours { get; set; } = 24;

    public int DefaultBatchSize { get; set; } = 500;

    public int DefaultLimit { get; set; } = 100000;

    /// <summary>
    /// When true, multiple event log channels are read concurrently during collect.
    /// </summary>
    public bool EnableParallelCollection { get; set; } = true;

    /// <summary>
    /// Maximum concurrent channel readers. 0 uses <see cref="Environment.ProcessorCount"/>.
    /// </summary>
    public int MaxDegreeOfParallelism { get; set; }
}

public sealed class AnalysisOptions
{
    /// <summary>
    /// When true, detection rules, correlation chains, and IOC scanning run concurrently.
    /// </summary>
    public bool EnableParallelAnalysis { get; set; } = true;

    /// <summary>
    /// Maximum worker threads for analysis. 0 uses <see cref="Environment.ProcessorCount"/>.
    /// </summary>
    public int MaxDegreeOfParallelism { get; set; }
}

public sealed class IocFeedOptions
{
    /// <summary>
    /// Maximum concurrent feed downloads. 0 uses <see cref="Environment.ProcessorCount"/>.
    /// </summary>
    public int MaxDegreeOfParallelism { get; set; }

    /// <summary>
    /// Per-feed HTTP download timeout in seconds.
    /// </summary>
    public int FeedTimeoutSeconds { get; set; } = 30;
}

public sealed class StartupOptions
{
    /// <summary>
    /// Download and import public IOC feeds before running commands.
    /// </summary>
    public bool AutoUpdateIocFeeds { get; set; } = true;

    /// <summary>
    /// Download SigmaHQ rules before running commands.
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
}
