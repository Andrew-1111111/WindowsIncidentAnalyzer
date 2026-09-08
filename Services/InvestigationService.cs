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
    ICveDetectionService cves,
    ICveDatabaseService cveDatabase,
    ISigmaRuleService sigmaRules,
    IMitreAttackService mitreAttack,
    IMitreAttackEnrichmentService mitreEnrichment,
    ILogger<InvestigationService> logger) : IInvestigationService
{
    public async Task<InvestigationSummary> AnalyzeAsync(EventQueryFilter? filter, CancellationToken cancellationToken)
    {
        await sigmaRules.EnsureLoadedAsync(cancellationToken);
        await mitreAttack.EnsureLoadedAsync(cancellationToken);
        await cveDatabase.EnsureLoadedAsync(cancellationToken);
        var count = await events.CountAsync(filter, cancellationToken);
        logger.LogInformation("Starting investigation analysis over {Count} event(s)", count);

        // Detection is the heavy CPU phase (especially Sigma). Correlation / IOC / CVE
        // each use their own EF contexts and can run concurrently afterward.
        var produced = await detection.AnalyzeAsync(filter, cancellationToken);
        mitreEnrichment.Enrich(produced);
        logger.LogInformation(
            "Analysis produced {FindingCount} finding(s); running correlation, IOC, and CVE scans in parallel",
            produced.Count);

        var chainsTask = correlation.CorrelateAsync(filter, cancellationToken);
        var matchesTask = iocs.ScanAsync(filter, cancellationToken);
        var cveMatchesTask = cves.ScanAsync(filter, cancellationToken);
        await Task.WhenAll(chainsTask, matchesTask, cveMatchesTask);

        var chains = await chainsTask;
        var matches = await matchesTask;
        var cveMatches = await cveMatchesTask;
        logger.LogInformation(
            "Analysis complete: {CorrelationCount} correlation(s), {IocCount} IOC match(es), {CveCount} CVE match(es)",
            chains.Count,
            matches.Count,
            cveMatches.Count);

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
            CveMatches = cveMatches,
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
                IocMatches = matches.Count,
                CveMatches = cveMatches.Count
            })
        }, cancellationToken);

        return summary;
    }
}
