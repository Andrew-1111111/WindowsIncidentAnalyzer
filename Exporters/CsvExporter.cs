using WindowsIncidentAnalyzer.Models;

namespace WindowsIncidentAnalyzer.Exporters;

public sealed class CsvExporter : IExporter
{
    public string Format => "csv";

    public Task ExportAsync(InvestigationExport data, string path, CancellationToken cancellationToken)
    {
        var directory = Path.GetDirectoryName(Path.GetFullPath(path));
        if (!string.IsNullOrEmpty(directory))
        {
            Directory.CreateDirectory(directory);
        }

        var stem = Path.Combine(
            directory ?? Directory.GetCurrentDirectory(),
            Path.GetFileNameWithoutExtension(path));

        var events = ExportRowBuilder.BuildEventMap(data);

        return ExportAllAsync(stem, data, events, cancellationToken);
    }

    private static async Task ExportAllAsync(
        string stem,
        InvestigationExport data,
        IReadOnlyDictionary<long, WindowsEvent> events,
        CancellationToken cancellationToken)
    {
        await ExcelSheetWriter.WriteAsync(
            stem + "-findings.xlsx",
            "Findings",
            ExportRowBuilder.BuildFindingRows(data.Findings, events),
            new FindingCsvRowMap(),
            cancellationToken);

        await ExcelSheetWriter.WriteAsync(
            stem + "-timeline.xlsx",
            "Timeline",
            ExportRowBuilder.BuildTimelineRows(data.Timeline),
            new TimelineCsvRowMap(),
            cancellationToken);

        await ExcelSheetWriter.WriteAsync(
            stem + "-iocs.xlsx",
            "IOCs",
            ExportRowBuilder.BuildIocRows(data.IocMatches),
            new IocCsvRowMap(),
            cancellationToken);

        await ExcelSheetWriter.WriteAsync(
            stem + "-correlations.xlsx",
            "Correlations",
            ExportRowBuilder.BuildCorrelationRows(data.Correlations),
            new CorrelationCsvRowMap(),
            cancellationToken);

        await ExcelSheetWriter.WriteAsync(
            stem + "-events.xlsx",
            "Events",
            ExportRowBuilder.BuildEventRows(data.Events),
            new EventCsvRowMap(),
            cancellationToken);

        await ExcelSheetWriter.WriteAsync(
            stem + "-statistics.xlsx",
            "Statistics",
            ExportRowBuilder.BuildStatisticsRows(data.Statistics, data.Filter),
            new StatisticsCsvRowMap(),
            cancellationToken);
    }
}
