using WindowsIncidentAnalyzer.Models;

namespace WindowsIncidentAnalyzer.Services;

public interface ICorrelationService
{
    IReadOnlyList<EventCorrelation> Correlate(IEnumerable<WindowsEvent> events);

    Task<IReadOnlyList<EventCorrelation>> CorrelateAsync(EventQueryFilter? filter, CancellationToken cancellationToken);
}
