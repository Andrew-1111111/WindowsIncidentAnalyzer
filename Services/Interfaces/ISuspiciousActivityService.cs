using WindowsIncidentAnalyzer.Models;

namespace WindowsIncidentAnalyzer.Services;

public interface ISuspiciousActivityService
{
    Task<IReadOnlyList<SecurityFinding>> AnalyzeAsync(EventQueryFilter? filter, CancellationToken cancellationToken);
}
