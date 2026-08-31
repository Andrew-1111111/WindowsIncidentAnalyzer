namespace WindowsIncidentAnalyzer.Services;

public interface IEventIngestionService
{
    Task<int> CollectAsync(CollectRequest request, CancellationToken cancellationToken);
}
