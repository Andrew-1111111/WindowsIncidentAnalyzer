using WindowsIncidentAnalyzer.Configuration;

namespace WindowsIncidentAnalyzer.Infrastructure;

public static class ParallelAnalysis
{
    public static int ResolveMaxDegreeOfParallelism(int maxDegreeOfParallelism) =>
        maxDegreeOfParallelism <= 0
            ? Math.Max(1, Environment.ProcessorCount)
            : maxDegreeOfParallelism;

    public static int ResolveMaxDegreeOfParallelism(AnalysisOptions options) =>
        ResolveMaxDegreeOfParallelism(options.MaxDegreeOfParallelism);

    public static int ResolveMaxDegreeOfParallelism(CollectionOptions options) =>
        ResolveMaxDegreeOfParallelism(options.MaxDegreeOfParallelism);

    public static int ResolveIocFeedParallelism(IocFeedOptions options)
    {
        const int defaultCap = 4;
        var degree = options.MaxDegreeOfParallelism <= 0
            ? Math.Min(defaultCap, Math.Max(1, Environment.ProcessorCount))
            : options.MaxDegreeOfParallelism;
        return Math.Max(1, degree);
    }

    public static ParallelOptions CreateOptions(AnalysisOptions options, CancellationToken cancellationToken) =>
        new()
        {
            MaxDegreeOfParallelism = ResolveMaxDegreeOfParallelism(options),
            CancellationToken = cancellationToken
        };

    /// <summary>
    /// Parallel options for CPU-bound work. Does not wire cancellation into worker threads
    /// to avoid noisy OperationCanceledException on every parallel worker.
    /// </summary>
    public static ParallelOptions CreateCpuBoundOptions(AnalysisOptions options) =>
        new()
        {
            MaxDegreeOfParallelism = ResolveMaxDegreeOfParallelism(options)
        };
}
