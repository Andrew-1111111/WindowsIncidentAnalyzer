using WindowsIncidentAnalyzer.Exporters;
using WindowsIncidentAnalyzer.Infrastructure;
using WindowsIncidentAnalyzer.Models;
using WindowsIncidentAnalyzer.Repositories;

namespace WindowsIncidentAnalyzer.Services;

public sealed class ExportService(
    IEnumerable<IExporter> exporters,
    IFindingRepository findings,
    ICorrelationRepository correlations,
    IIocDetectionService iocs,
    ICveDetectionService cves,
    ITimelineService timeline,
    IStatisticsService statistics,
    IEventRepository events,
    IMitreAttackEnrichmentService mitreEnrichment) : IExportService
{
    public async Task<string> ExportAsync(string format, string? outputPath, EventQueryFilter filter, CancellationToken cancellationToken)
    {
        var key = format.Trim().TrimStart('.').ToLowerInvariant();
        var exporter = exporters.FirstOrDefault(e => e.Format.Equals(key, StringComparison.OrdinalIgnoreCase))
                       ?? throw new ArgumentException($"Unsupported export format '{format}'. Use csv, json, or html.");

        var path = outputPath;
        if (string.IsNullOrWhiteSpace(path))
        {
            var ext = key == "csv" ? "csv" : key;
            path = Path.Combine("data", $"investigation-{DateTime.UtcNow:yyyyMMdd-HHmmss}.{ext}");
        }

        var findingsList = await findings.GetAllAsync(50_000, cancellationToken);
        mitreEnrichment.Enrich(findingsList);
        if (ExportQueryFilter.HasCriteria(filter))
        {
            findingsList = ExportQueryFilter.FilterFindings(findingsList, filter);
        }

        var correlationsList = await correlations.GetAllAsync(50_000, cancellationToken);
        if (ExportQueryFilter.HasCriteria(filter))
        {
            correlationsList = ExportQueryFilter.FilterCorrelations(correlationsList, filter);
        }

        var iocMatches = await iocs.ScanAsync(filter, cancellationToken);
        var cveMatches = await cves.ScanAsync(filter, cancellationToken);
        if (ExportQueryFilter.HasCriteria(filter))
        {
            iocMatches = ExportQueryFilter.FilterIocMatches(iocMatches, filter);
            cveMatches = ExportQueryFilter.FilterCveMatches(cveMatches, filter);
        }

        var timelineItems = await timeline.BuildAsync(
            filter with { Limit = filter.Limit <= 0 ? 50_000 : filter.Limit },
            cancellationToken);

        var data = new InvestigationExport
        {
            Title = "Windows Incident Investigation",
            GeneratedUtc = DateTime.UtcNow,
            Filter = filter,
            Statistics = await statistics.GetAsync(filter, cancellationToken),
            Findings = findingsList,
            Correlations = correlationsList,
            IocMatches = iocMatches,
            CveMatches = cveMatches,
            Timeline = timelineItems
        };

        var eventRowIds = InvestigationExportCollector.CollectEventRowIds(data);
        if (eventRowIds.Count > 0)
        {
            var eventMap = await events.GetByRowIdsAsync(eventRowIds, cancellationToken);
            data.Events = eventMap.Values
                .OrderBy(evt => evt.TimeCreatedUtc)
                .ThenBy(evt => evt.Id)
                .ToList();
            FindingContextHydrator.FillGaps(findingsList, eventMap);
        }

        await exporter.ExportAsync(data, path, cancellationToken);
        return Path.GetFullPath(path);
    }
}
