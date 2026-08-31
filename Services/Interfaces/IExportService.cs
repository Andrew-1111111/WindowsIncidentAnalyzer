using WindowsIncidentAnalyzer.Models;

namespace WindowsIncidentAnalyzer.Services;

public interface IExportService
{
    Task<string> ExportAsync(string format, string? outputPath, EventQueryFilter filter, CancellationToken cancellationToken);
}
