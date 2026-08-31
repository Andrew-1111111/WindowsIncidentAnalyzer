using System.Diagnostics.Eventing.Reader;
using System.Runtime.CompilerServices;
using Microsoft.Extensions.Logging;
using WindowsIncidentAnalyzer.Models;

namespace WindowsIncidentAnalyzer.Services;

public sealed class EvtxParserService(IEventLogService eventLogService, ILogger<EvtxParserService> logger) : IEvtxParserService
{
    public async IAsyncEnumerable<WindowsEvent> ParseFileAsync(
        string path,
        EventLogQueryOptions options,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            throw new ArgumentException("EVTX path is required.", nameof(path));
        }

        var fullPath = Path.GetFullPath(path);
        if (!File.Exists(fullPath))
        {
            throw new FileNotFoundException("EVTX file was not found.", fullPath);
        }

        try
        {
            using var probe = File.Open(fullPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
        }
        catch (UnauthorizedAccessException)
        {
            throw;
        }
        catch (IOException ex)
        {
            logger.LogError(ex, "Cannot open EVTX file {Path} for read-only access", fullPath);
            throw;
        }

        logger.LogInformation("Reading EVTX file {Path} in read-only mode", fullPath);

        var yielded = 0;
        await foreach (var evt in eventLogService.ReadChannelAsync(fullPath, PathType.FilePath, options, cancellationToken))
        {
            yield return evt;
            yielded++;
            if (options.Limit is { } limit && yielded >= limit)
            {
                yield break;
            }
        }
    }
}
