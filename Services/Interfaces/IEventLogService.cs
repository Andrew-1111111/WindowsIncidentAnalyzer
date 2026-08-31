using System.Diagnostics.Eventing.Reader;
using WindowsIncidentAnalyzer.Models;

namespace WindowsIncidentAnalyzer.Services;

public interface IEventLogService
{
    IAsyncEnumerable<WindowsEvent> CollectAsync(EventLogQueryOptions options, CancellationToken cancellationToken);

    IAsyncEnumerable<WindowsEvent> ReadChannelAsync(
        string path,
        PathType pathType,
        EventLogQueryOptions options,
        CancellationToken cancellationToken);
}
