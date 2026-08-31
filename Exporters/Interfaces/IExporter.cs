namespace WindowsIncidentAnalyzer.Exporters;

public interface IExporter
{
    string Format { get; }

    Task ExportAsync(InvestigationExport data, string path, CancellationToken cancellationToken);
}
