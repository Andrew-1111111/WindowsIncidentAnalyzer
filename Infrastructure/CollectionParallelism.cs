using WindowsIncidentAnalyzer.Configuration;

namespace WindowsIncidentAnalyzer.Infrastructure;

public static class CollectionParallelism
{
    public static bool ShouldUseParallel(CollectionOptions options, int channelCount) =>
        options.EnableParallelCollection && channelCount > 1;
}
