using WindowsIncidentAnalyzer.Models;

namespace WindowsIncidentAnalyzer.Repositories;

public interface IFindingRepository
{
    Task InsertManyAsync(IReadOnlyList<SecurityFinding> findings, CancellationToken cancellationToken);

    Task<IReadOnlyList<SecurityFinding>> GetAllAsync(int limit, CancellationToken cancellationToken);

    Task ClearAsync(CancellationToken cancellationToken);
}
