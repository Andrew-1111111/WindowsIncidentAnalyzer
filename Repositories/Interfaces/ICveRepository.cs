using WindowsIncidentAnalyzer.Models;

namespace WindowsIncidentAnalyzer.Repositories;

public interface ICveRepository
{
    Task ReplaceAllAsync(IReadOnlyList<CveRecord> records, CancellationToken cancellationToken);

    Task<IReadOnlyList<CveRecord>> GetAllAsync(CancellationToken cancellationToken);

    int Count { get; }
}
