using WindowsIncidentAnalyzer.Exporters;
using WindowsIncidentAnalyzer.Models;
using WindowsIncidentAnalyzer.Repositories;

namespace WindowsIncidentAnalyzer.Services;

public sealed class ExportService(
    IEnumerable<IExporter> exporters,
    IFindingRepository findings,
    ICorrelationRepository correlations,
    IIocDetectionService iocs,
    ITimelineService timeline,
    IStatisticsService statistics,
    IEventRepository events) : IExportService
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
        var correlationsList = await correlations.GetAllAsync(50_000, cancellationToken);
        var iocMatches = await iocs.ScanAsync(filter, cancellationToken);
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
        }

        await exporter.ExportAsync(data, path, cancellationToken);
        return Path.GetFullPath(path);
    }
}
