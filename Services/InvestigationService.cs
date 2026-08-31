using System.Text.Json;
using Microsoft.Extensions.Logging;
using WindowsIncidentAnalyzer.Models;
using WindowsIncidentAnalyzer.Repositories;

namespace WindowsIncidentAnalyzer.Services;

public sealed class InvestigationService(
    IEventRepository events,
    IFindingRepository findings,
    ICorrelationRepository correlations,
    IIncidentRepository incidents,
    ISuspiciousActivityService detection,
    ICorrelationService correlation,
    IIocDetectionService iocs,
    ISigmaRuleService sigmaRules,
    ILogger<InvestigationService> logger) : IInvestigationService
{
    public async Task<InvestigationSummary> AnalyzeAsync(EventQueryFilter? filter, CancellationToken cancellationToken)
    {
        await sigmaRules.EnsureLoadedAsync(cancellationToken);
        var count = await events.CountAsync(filter, cancellationToken);
        logger.LogInformation("Starting investigation analysis over {Count} event(s)", count);

        // Run sequentially through the DB-heavy phases to avoid triple concurrent reads of the same
        // event store. CPU-bound detector/correlation/IOC work still parallelizes internally.
        var produced = await detection.AnalyzeAsync(filter, cancellationToken);
        var chains = await correlation.CorrelateAsync(filter, cancellationToken);
        var matches = await iocs.ScanAsync(filter, cancellationToken);

        await findings.ClearAsync(cancellationToken);
        await correlations.ClearAsync(cancellationToken);
        await findings.InsertManyAsync(produced, cancellationToken);
        await correlations.InsertManyAsync(chains, cancellationToken);

        var summary = new InvestigationSummary
        {
            EventsAnalyzed = count,
            Findings = produced,
            Correlations = chains,
            IocMatches = matches,
            TopSuspiciousUsers = produced
                .Select(f => f.User)
                .Where(u => !string.IsNullOrWhiteSpace(u))
                .GroupBy(u => u!, StringComparer.OrdinalIgnoreCase)
                .OrderByDescending(g => g.Count())
                .Take(5)
                .Select(g => g.Key)
                .ToList(),
            TopSuspiciousIps = produced
                .Select(f => f.SourceIpAddress)
                .Where(ip => !string.IsNullOrWhiteSpace(ip))
                .GroupBy(ip => ip!, StringComparer.OrdinalIgnoreCase)
                .OrderByDescending(g => g.Count())
                .Take(5)
                .Select(g => g.Key)
                .ToList()
        };

        await incidents.InsertAsync(new Incident
        {
            Title = "Windows investigation",
            CreatedUtc = DateTime.UtcNow,
            EventsAnalyzed = count,
            FindingsCritical = summary.CriticalCount,
            FindingsHigh = summary.HighCount,
            FindingsMedium = summary.MediumCount,
            FindingsLow = summary.LowCount,
            FindingsInfo = summary.InfoCount,
            SummaryJson = JsonSerializer.Serialize(new
            {
                summary.TopSuspiciousUsers,
                summary.TopSuspiciousIps,
                Correlations = chains.Count,
                IocMatches = matches.Count
            })
        }, cancellationToken);

        return summary;
    }
}
