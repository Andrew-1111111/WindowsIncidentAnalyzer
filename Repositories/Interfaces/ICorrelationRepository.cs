using WindowsIncidentAnalyzer.Models;

namespace WindowsIncidentAnalyzer.Repositories;

public interface ICorrelationRepository
{
    Task InsertManyAsync(IReadOnlyList<EventCorrelation> correlations, CancellationToken cancellationToken);

    Task<IReadOnlyList<EventCorrelation>> GetAllAsync(int limit, CancellationToken cancellationToken);

    Task ClearAsync(CancellationToken cancellationToken);
}
