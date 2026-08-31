using WindowsIncidentAnalyzer.Models;

namespace WindowsIncidentAnalyzer.Services;

public interface IStatisticsService
{
    Task<StatisticsResult> GetAsync(EventQueryFilter? filter, CancellationToken cancellationToken);
}
