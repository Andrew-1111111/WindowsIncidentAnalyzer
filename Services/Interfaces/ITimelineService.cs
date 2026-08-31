using WindowsIncidentAnalyzer.Models;

namespace WindowsIncidentAnalyzer.Services;

public interface ITimelineService
{
    Task<IReadOnlyList<TimelineItem>> BuildAsync(EventQueryFilter filter, CancellationToken cancellationToken);
}
