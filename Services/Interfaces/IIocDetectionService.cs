using WindowsIncidentAnalyzer.Models;

namespace WindowsIncidentAnalyzer.Services;

public interface IIocDetectionService
{
    IReadOnlyList<IocMatch> Scan(IEnumerable<WindowsEvent> events, IEnumerable<Ioc> iocs);

    Task<IReadOnlyList<IocMatch>> ScanAsync(EventQueryFilter? filter, CancellationToken cancellationToken);
}
