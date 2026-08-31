using WindowsIncidentAnalyzer.Detectors;
using WindowsIncidentAnalyzer.Models;
using WindowsIncidentAnalyzer.Repositories;

namespace WindowsIncidentAnalyzer.Services;

public sealed class TimelineService(IEventRepository events, IFindingRepository findings) : ITimelineService
{
    public async Task<IReadOnlyList<TimelineItem>> BuildAsync(EventQueryFilter filter, CancellationToken cancellationToken)
    {
        var records = await events.QueryAsync(filter, cancellationToken);
        var findingList = await findings.GetAllAsync(10_000, cancellationToken);
        var byRow = findingList
            .SelectMany(f => f.RelatedEventRowIds.Select(id => (id, f)))
            .GroupBy(x => x.id)
            .ToDictionary(g => g.Key, g => g.Max(x => x.f.Severity));

        return records
            .Select(evt =>
            {
                var severity = DetectionSeverity.Info;
                if (evt.Id > 0 && byRow.TryGetValue(evt.Id, out var mapped))
                {
                    severity = mapped;
                }

                return new TimelineItem
                {
                    TimestampUtc = evt.TimeCreatedUtc,
                    Host = evt.ComputerName,
                    EventId = evt.EventId,
                    Source = evt.LogName ?? evt.ProviderName,
                    User = evt.TargetUserName ?? evt.User,
                    Process = evt.ProcessName,
                    Ip = evt.SourceIpAddress ?? evt.DestinationIpAddress,
                    Description = EventFieldMapper.Describe(evt),
                    Severity = severity,
                    EventRowId = evt.Id
                };
            })
            .OrderBy(t => t.TimestampUtc)
            .ToList();
    }
}
