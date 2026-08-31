using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Spectre.Console;
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
                AnsiConsole.MarkupLine("[grey]Running elevated: Security and Sysmon channels can be read.[/]");
            }
            else
            {
                AnsiConsole.MarkupLine("[yellow]Running without Administrator.[/]");
                AnsiConsole.MarkupLine("[grey]Security (and often Sysmon) will be skipped if access is denied.[/]");
                AnsiConsole.MarkupLine("[grey]Application, System, PowerShell, and EVTX files do not require elevation.[/]");
            }
        }

        var batchSize = request.BatchSize > 0 ? request.BatchSize : options.Value.Collection.DefaultBatchSize;
        var source = string.IsNullOrWhiteSpace(request.EvtxPath)
            ? eventLog.CollectAsync(query, cancellationToken)
            : evtx.ParseFileAsync(request.EvtxPath, query, cancellationToken);

        var batch = new List<WindowsEvent>(batchSize);
        var total = 0;
        var processed = 0;
        var skippedLogs = 0;

        await AnsiConsole.Status()
            .AutoRefresh(true)
            .Spinner(Spinner.Known.Dots)
            .StartAsync("Collecting Windows events...", async ctx =>
            {
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
                        ctx.Status($"Collecting... {processed:N0} processed, {total:N0} stored or updated");
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
                    ctx.Status($"Collecting... {processed:N0} processed, {total:N0} stored or updated");
                }
            });

        AnsiConsole.WriteLine();

        if (skippedLogs > 0)
        {
            logger.LogWarning("Skipped {Count} events due to insert errors", skippedLogs);
        }

        logger.LogInformation("Ingested {Count} events", total);
        return total;
    }
}
