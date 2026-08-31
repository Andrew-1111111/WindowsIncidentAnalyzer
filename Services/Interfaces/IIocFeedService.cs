using WindowsIncidentAnalyzer.Models;

namespace WindowsIncidentAnalyzer.Services;

public interface IIocFeedService
{
    Task<IReadOnlyList<Ioc>> DownloadAsync(
        CancellationToken cancellationToken,
        IProgress<string>? progress = null);
}
