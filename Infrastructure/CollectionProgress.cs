namespace WindowsIncidentAnalyzer.Infrastructure;

internal sealed class CollectionProgress
{
    private volatile bool _stopRequested;

    public CollectionProgress(int? limit)
    {
        Limit = limit is > 0 ? limit.Value : int.MaxValue;
    }

    public int Limit { get; }

    public bool IsStopped => _stopRequested;

    public void RequestStop() => _stopRequested = true;

    public bool ShouldContinueReading() => !_stopRequested;
}
