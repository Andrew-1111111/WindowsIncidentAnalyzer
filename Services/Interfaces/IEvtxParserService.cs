using WindowsIncidentAnalyzer.Models;

namespace WindowsIncidentAnalyzer.Services;

public interface IEvtxParserService
{
    IAsyncEnumerable<WindowsEvent> ParseFileAsync(string path, EventLogQueryOptions options, CancellationToken cancellationToken);
}
