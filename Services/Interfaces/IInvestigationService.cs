using WindowsIncidentAnalyzer.Models;

namespace WindowsIncidentAnalyzer.Services;

public interface IInvestigationService
{
    Task<InvestigationSummary> AnalyzeAsync(EventQueryFilter? filter, CancellationToken cancellationToken);
}
