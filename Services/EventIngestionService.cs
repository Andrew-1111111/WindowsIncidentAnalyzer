using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using WindowsIncidentAnalyzer.Configuration;
using WindowsIncidentAnalyzer.Infrastructure;
using WindowsIncidentAnalyzer.Models;
using WindowsIncidentAnalyzer.Repositories;

namespace WindowsIncidentAnalyzer.Services;

public sealed class CollectRequest
{
    public string? LogName { get; init; }

    public string? EvtxPath { get; init; }

    public DateTime? FromUtc { get; init; }

    public DateTime? ToUtc { get; init; }

    public IReadOnlyList<TimeRange>? TimeRanges { get; init; }

    public IReadOnlyList<int>? EventIds { get; init; }

    public int? Limit { get; init; }

    public int BatchSize { get; init; } = 500;

    public List<string> AccessDeniedLogs { get; } = [];

    public List<string> MissingLogs { get; } = [];
}

public sealed class EventIngestionService(
    IEventLogService eventLog,
    IEvtxParserService evtx,
    IEventRepository repository,
    IOptions<AnalyzerOptions> options,
    ILogger<EventIngestionService> logger) : IEventIngestionService
{
    public async Task<int> CollectAsync(CollectRequest request, CancellationToken cancellationToken)
    {
        var query = new EventLogQueryOptions
        {
            LogName = request.LogName,
            EvtxPath = request.EvtxPath,
            FromUtc = request.FromUtc,
            ToUtc = request.ToUtc,
            TimeRanges = request.TimeRanges,
            EventIds = request.EventIds,
            Limit = request.Limit,
            ThrowOnAccessDenied = !string.IsNullOrWhiteSpace(request.LogName),
            AccessDeniedLogs = request.AccessDeniedLogs,
            MissingLogs = request.MissingLogs
        };

        if (string.IsNullOrWhiteSpace(request.EvtxPath))
        {
            if (ProcessElevation.IsAdministrator())
            {
                WriteLine("Running elevated: Security and Sysmon channels can be read.");
            }
            else
            {
                WriteLine("Running without Administrator.");
                WriteLine("Security (and often Sysmon) will be skipped if access is denied.");
                WriteLine("Application, System, PowerShell, and EVTX files do not require elevation.");
            }
        }

        var batchSize = request.BatchSize > 0 ? request.BatchSize : options.Value.Collection.DefaultBatchSize;
        var collection = options.Value.Collection;
        var source = string.IsNullOrWhiteSpace(request.EvtxPath)
            ? eventLog.CollectAsync(query, cancellationToken)
            : evtx.ParseFileAsync(request.EvtxPath, query, cancellationToken);

        var batch = new List<WindowsEvent>(batchSize);
        var total = 0;
        var processed = 0;
        var skippedLogs = 0;

        if (string.IsNullOrWhiteSpace(request.EvtxPath) &&
            (string.IsNullOrWhiteSpace(request.LogName) || WindowsLogCatalog.IsAllLogsAlias(request.LogName)))
        {
            var channelCount = WindowsLogCatalog.ResolveCollectionLogs(
                request.LogName,
                collection.CollectAllLogs,
                collection.IncludeAnalyticDebugLogs,
                discoverFromEvtxFiles: false).Count;
            if (ParallelAnalysis.ShouldUseParallel(options.Value, channelCount))
            {
                var workers = ParallelAnalysis.ResolveCollectionParallelism(options.Value, channelCount);
                WriteLine($"Collecting Windows events in parallel ({channelCount} channel(s), {workers} worker(s))...");
            }
            else
            {
                WriteLine("Collecting Windows events...");
            }
        }
        else
        {
            WriteLine("Collecting Windows events...");
        }

        await foreach (var evt in source.WithCancellation(cancellationToken))
        {
            batch.Add(evt);
            if (batch.Count < batchSize)
            {
                continue;
            }

            try
            {
                processed += batch.Count;
                total += await repository.InsertBatchAsync(batch, cancellationToken);
                WriteProgress(processed, total);
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Failed to insert a batch of {Count} events", batch.Count);
                skippedLogs += batch.Count;
            }

            batch.Clear();
        }

        if (batch.Count > 0)
        {
            processed += batch.Count;
            total += await repository.InsertBatchAsync(batch, cancellationToken);
            WriteProgress(processed, total);
        }

        EndProgressLine();

        if (skippedLogs > 0)
        {
            logger.LogWarning("Skipped {Count} events due to insert errors", skippedLogs);
        }

        logger.LogInformation("Ingested {Count} events", total);
        return total;
    }

    private static void WriteProgress(int processed, int total)
    {
        var message = $"Collecting... {processed:N0} processed, {total:N0} stored or updated";
        try
        {
            if (!Console.IsOutputRedirected)
            {
                // Same single status line as Spectre Status (without GetBufferInfo noise).
                Console.Out.Write('\r');
                Console.Out.Write(message);
                if (message.Length < 80)
                {
                    Console.Out.Write(new string(' ', 80 - message.Length));
                }

                Console.Out.Flush();
                return;
            }

            Console.Out.WriteLine(message);
        }
        catch
        {
            // Console may be detached under some hosts; never fail collect for UI.
        }
    }

    private static void EndProgressLine()
    {
        try
        {
            if (!Console.IsOutputRedirected)
            {
                Console.Out.WriteLine();
            }
            else
            {
                Console.Out.WriteLine();
            }
        }
        catch
        {
            // Ignore detached console.
        }
    }

    private static void WriteLine(string message)
    {
        try
        {
            Console.Out.WriteLine(message);
        }
        catch
        {
            // Console may be detached under some hosts; never fail collect for UI.
        }
    }
}
