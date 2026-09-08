using WindowsIncidentAnalyzer.Models;

namespace WindowsIncidentAnalyzer.Services;

public interface ICveDetectionService
{
    Task<IReadOnlyList<CveMatch>> ScanAsync(EventQueryFilter? filter, CancellationToken cancellationToken);
}
