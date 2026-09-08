using WindowsIncidentAnalyzer.Models;

namespace WindowsIncidentAnalyzer.Services;

public interface IMitreAttackEnrichmentService
{
    void Enrich(FindingContext context);

    void Enrich(IEnumerable<SecurityFinding> findings);
}
