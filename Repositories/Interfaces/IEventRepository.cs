using WindowsIncidentAnalyzer.Models;

namespace WindowsIncidentAnalyzer.Repositories;

public interface IEventRepository
{
    Task<int> InsertBatchAsync(IReadOnlyList<WindowsEvent> events, CancellationToken cancellationToken);

    Task<IReadOnlyList<WindowsEvent>> QueryAsync(EventQueryFilter filter, CancellationToken cancellationToken);

    Task<int> CountAsync(EventQueryFilter? filter, CancellationToken cancellationToken);

    Task<IReadOnlyList<WindowsEvent>> GetByEventIdsAsync(
        IReadOnlyList<int> eventIds,
        EventQueryFilter? filter,
        CancellationToken cancellationToken);

    Task<IReadOnlyDictionary<long, WindowsEvent>> GetByRowIdsAsync(
        IReadOnlyList<long> rowIds,
        CancellationToken cancellationToken);
}
