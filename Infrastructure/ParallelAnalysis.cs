using WindowsIncidentAnalyzer.Configuration;

namespace WindowsIncidentAnalyzer.Infrastructure;

public static class ParallelAnalysis
{
    /// <summary>
    /// Resolves worker count for <see cref="ParallelOptions"/>.
    /// Config 0 = unlimited (-1 for the TPL); otherwise the configured value.
    /// </summary>
    public static int ResolveMaxDegreeOfParallelism(int maxDegreeOfParallelism) =>
        maxDegreeOfParallelism <= 0 ? -1 : Math.Max(1, maxDegreeOfParallelism);

    public static int ResolveMaxDegreeOfParallelism(AnalyzerOptions options) =>
        ResolveMaxDegreeOfParallelism(options.MaxDegreeOfParallelism);

    /// <summary>
    /// Resolves workers for a known work-item count (channels, feeds, detectors).
    /// Config 0 = unlimited (all items); otherwise clamped to <paramref name="itemCount"/>.
    /// </summary>
    public static int ResolveBoundedParallelism(int maxDegreeOfParallelism, int itemCount)
    {
        itemCount = Math.Max(1, itemCount);
        if (maxDegreeOfParallelism <= 0)
        {
            return itemCount;
        }

        return Math.Clamp(maxDegreeOfParallelism, 1, itemCount);
    }

    public static int ResolveCollectionParallelism(AnalyzerOptions options, int channelCount) =>
        ResolveBoundedParallelism(options.MaxDegreeOfParallelism, channelCount);

    public static int ResolveIocFeedParallelism(AnalyzerOptions options, int feedCount) =>
        ResolveBoundedParallelism(options.MaxDegreeOfParallelism, feedCount);

    public static bool ShouldUseParallel(int maxDegreeOfParallelism, int itemCount) =>
        itemCount > 1 && (maxDegreeOfParallelism <= 0 || maxDegreeOfParallelism > 1);

    public static bool ShouldUseParallel(AnalyzerOptions options, int itemCount) =>
        ShouldUseParallel(options.MaxDegreeOfParallelism, itemCount);

    public static ParallelOptions CreateOptions(AnalyzerOptions options, CancellationToken cancellationToken) =>
        new()
        {
            MaxDegreeOfParallelism = ResolveMaxDegreeOfParallelism(options),
            CancellationToken = cancellationToken
        };

    /// <summary>
    /// Parallel options for CPU-bound work. Does not wire cancellation into worker threads
    /// to avoid noisy OperationCanceledException on every parallel worker.
    /// </summary>
    public static ParallelOptions CreateCpuBoundOptions(AnalyzerOptions options) =>
        new()
        {
            MaxDegreeOfParallelism = ResolveMaxDegreeOfParallelism(options)
        };
}
