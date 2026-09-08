using System.ComponentModel;
using System.Diagnostics.Eventing.Reader;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading.Channels;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using WindowsIncidentAnalyzer.Configuration;
using WindowsIncidentAnalyzer.Infrastructure;
using WindowsIncidentAnalyzer.Models;

namespace WindowsIncidentAnalyzer.Services;

/// <summary>
/// Live collection mirrors the GitHub implementation: open channels by
/// <see cref="PathType.LogName"/>, read with <see cref="EventLogReader.ReadEvent"/>,
/// skip missing/denied channels. EVTX files are only used via <c>--evtx</c>.
/// </summary>
public sealed class EventLogService(
    EventRecordNormalizer normalizer,
    IOptions<AnalyzerOptions> options,
    ILogger<EventLogService> logger) : IEventLogService
{
    public async IAsyncEnumerable<WindowsEvent> CollectAsync(
        EventLogQueryOptions queryOptions,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        var logs = ResolveLogs(queryOptions);
        var collection = options.Value.Collection;

        // Multi-channel live collect prefers parallel readers when MaxDegreeOfParallelism allows it.
        var useParallel = ParallelAnalysis.ShouldUseParallel(options.Value, logs.Count);
        if (useParallel)
        {
            var workers = ParallelAnalysis.ResolveCollectionParallelism(options.Value, logs.Count);
            logger.LogInformation(
                "Collecting {Count} event log channel(s) in parallel (workers={Workers})",
                logs.Count,
                workers);

            await foreach (var evt in CollectParallelAsync(logs, queryOptions, collection, cancellationToken))
            {
                yield return evt;
            }

            yield break;
        }

        if (logs.Count > 0)
        {
            logger.LogInformation("Collecting {Count} event log channel(s) sequentially", logs.Count);
        }

        await foreach (var evt in CollectSequentialAsync(logs, queryOptions, cancellationToken))
        {
            yield return evt;
        }
    }

    public async IAsyncEnumerable<WindowsEvent> ReadChannelAsync(
        string path,
        PathType pathType,
        EventLogQueryOptions queryOptions,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        EventLogQuery query;
        try
        {
            var xpath = BuildXPath(queryOptions);
            query = string.IsNullOrEmpty(xpath)
                ? new EventLogQuery(path, pathType)
                : new EventLogQuery(path, pathType, xpath);
        }
        catch (Exception ex)
        {
            logger.LogDebug(ex, "XPath query rejected for {Path}; falling back to unfiltered read", path);
            query = new EventLogQuery(path, pathType);
        }

        // Never call EventLogReader for channels we already know are missing.
        if (pathType == PathType.LogName && WindowsLogCatalog.IsKnownMissingChannel(path))
        {
            TrackMissingLog(queryOptions, path);
            yield break;
        }

        EventLogReader? reader = null;
        try
        {
            reader = new EventLogReader(query);
        }
        catch (EventLogNotFoundException)
        {
            // Expected for optional channels; mark and continue without rethrowing.
            if (pathType == PathType.LogName)
            {
                WindowsLogCatalog.MarkMissingChannel(path);
            }

            logger.LogDebug("Event log {Path} was not found", path);
            TrackMissingLog(queryOptions, path);
            yield break;
        }
        catch (Exception ex) when (IsAccessDenied(ex))
        {
            logger.LogDebug(ex, "Access denied to event log {Path}", path);
            TrackAccessDenied(queryOptions, path);
            if (queryOptions.ThrowOnAccessDenied)
            {
                throw new UnauthorizedAccessException(
                    $"Cannot read event log '{path}'. The Security log (and often Sysmon) require Administrator rights or membership in Event Log Readers. Other commands (search, analyze, EVTX files) do not.",
                    ex);
            }

            yield break;
        }
        catch (EventLogException ex)
        {
            logger.LogDebug(ex, "Cannot open event log {Path}", path);
            TrackMissingLog(queryOptions, path);
            yield break;
        }

        using (reader)
        {
            var preferNativeXml = pathType == PathType.FilePath ||
                                  EventRecordNormalizer.ShouldTryNativeXml(path, providerName: null);

            while (true)
            {
                cancellationToken.ThrowIfCancellationRequested();
                EventRecord? record;
                try
                {
                    record = reader.ReadEvent();
                }
                catch (EventLogNotFoundException)
                {
                    break;
                }
                catch (EventLogException)
                {
                    continue;
                }
                catch (InvalidOperationException)
                {
                    break;
                }

                if (record == null)
                {
                    break;
                }

                WindowsEvent? parsed;
                using (record)
                {
                    if (!Matches(record, queryOptions))
                    {
                        continue;
                    }

                    parsed = normalizer.TryNormalize(record, preferNativeXml);
                }

                if (parsed != null)
                {
                    yield return parsed;
                }
            }
        }
    }

    private async IAsyncEnumerable<WindowsEvent> CollectSequentialAsync(
        IReadOnlyList<string> logs,
        EventLogQueryOptions queryOptions,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        var yielded = 0;
        foreach (var logName in logs)
        {
            cancellationToken.ThrowIfCancellationRequested();
            await foreach (var evt in ReadChannelAsync(logName, PathType.LogName, queryOptions, cancellationToken))
            {
                yield return evt;
                yielded++;
                if (queryOptions.Limit is > 0 && yielded >= queryOptions.Limit)
                {
                    yield break;
                }
            }
        }
    }

    private async IAsyncEnumerable<WindowsEvent> CollectParallelAsync(
        IReadOnlyList<string> logs,
        EventLogQueryOptions queryOptions,
        CollectionOptions collection,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        var progress = new CollectionProgress(queryOptions.Limit);
        var capacity = Math.Max(collection.DefaultBatchSize * 2, 1000);
        var channel = Channel.CreateBounded<WindowsEvent>(new BoundedChannelOptions(capacity)
        {
            FullMode = BoundedChannelFullMode.Wait,
            SingleReader = true,
            SingleWriter = false
        });

        using var stopCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var producer = ProduceChannelsAsync(logs, queryOptions, collection, progress, channel.Writer, stopCts);

        var yielded = 0;
        try
        {
            await foreach (var evt in channel.Reader.ReadAllAsync(cancellationToken))
            {
                yielded++;
                if (queryOptions.Limit is > 0 && yielded > queryOptions.Limit)
                {
                    progress.RequestStop();
                    stopCts.Cancel();
                    break;
                }

                yield return evt;
            }
        }
        finally
        {
            progress.RequestStop();
            stopCts.Cancel();
            channel.Writer.TryComplete();

            var shutdownSeconds = Math.Max(1, collection.ChannelShutdownTimeoutSeconds);
            try
            {
                await producer.WaitAsync(TimeSpan.FromSeconds(shutdownSeconds), CancellationToken.None)
                    .ConfigureAwait(false);
            }
            catch (TimeoutException)
            {
                logger.LogDebug(
                    "Timed out after {Seconds}s waiting for event log readers to stop",
                    shutdownSeconds);
            }
        }
    }

    private async Task ProduceChannelsAsync(
        IReadOnlyList<string> logs,
        EventLogQueryOptions queryOptions,
        CollectionOptions collection,
        CollectionProgress progress,
        ChannelWriter<WindowsEvent> writer,
        CancellationTokenSource stopCts)
    {
        try
        {
            var parallelism = ParallelAnalysis.ResolveCollectionParallelism(options.Value, logs.Count);
            await Parallel.ForEachAsync(
                logs,
                new ParallelOptions
                {
                    MaxDegreeOfParallelism = parallelism,
                    CancellationToken = stopCts.Token
                },
                async (logName, ct) =>
                {
                    await foreach (var evt in ReadChannelAsync(logName, PathType.LogName, queryOptions, ct))
                    {
                        if (!progress.ShouldContinueReading())
                        {
                            break;
                        }

                        try
                        {
                            await writer.WriteAsync(evt, ct).ConfigureAwait(false);
                        }
                        catch (ChannelClosedException)
                        {
                            break;
                        }
                        catch (OperationCanceledException) when (stopCts.IsCancellationRequested)
                        {
                            break;
                        }
                    }
                }).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (stopCts.IsCancellationRequested)
        {
            // Limit reached or user cancelled collection.
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Parallel event log collection failed");
            writer.TryComplete(ex);
            return;
        }

        writer.TryComplete();
    }

    /// <summary>
    /// GitHub-compatible resolution: default channel set, optional --log, optional collect-all
    /// from the registry. Missing optional channels (Sysmon) are filtered out before open.
    /// </summary>
    private List<string> ResolveLogs(EventLogQueryOptions queryOptions)
    {
        var collection = options.Value.Collection;
        IReadOnlyList<string> names;

        if (!string.IsNullOrWhiteSpace(queryOptions.LogName))
        {
            if (WindowsLogCatalog.IsAllLogsAlias(queryOptions.LogName))
            {
                names = WindowsLogCatalog.DiscoverLogNames(
                    collection.IncludeAnalyticDebugLogs,
                    discoverFromEvtxFiles: false);
            }
            else
            {
                // Explicit --log: attempt exactly that channel (MissingLogs reported on failure).
                return [WindowsLogNames.Resolve(queryOptions.LogName)];
            }
        }
        else if (collection.CollectAllLogs)
        {
            names = WindowsLogCatalog.DiscoverLogNames(
                collection.IncludeAnalyticDebugLogs,
                discoverFromEvtxFiles: false);
        }
        else
        {
            // Same default set as GitHub origin/master.
            names = WindowsLogNames.DefaultCollectionLogs;
        }

        return names
            .Where(name => !WindowsLogCatalog.IsKnownMissingChannel(name))
            .Where(WindowsLogCatalog.IsPresentChannel)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private static void TrackAccessDenied(EventLogQueryOptions options, string path)
    {
        if (options.AccessDeniedLogs is null)
        {
            return;
        }

        lock (options.AccessDeniedLogs)
        {
            options.AccessDeniedLogs.Add(path);
        }
    }

    private static void TrackMissingLog(EventLogQueryOptions options, string path)
    {
        if (options.MissingLogs is null)
        {
            return;
        }

        lock (options.MissingLogs)
        {
            options.MissingLogs.Add(path);
        }
    }

    private static bool IsAccessDenied(Exception ex)
    {
        if (ex is UnauthorizedAccessException)
        {
            return true;
        }

        if (ex is EventLogException eventLog)
        {
            return eventLog.HResult is 5 or unchecked((int)0x80070005)
                   || WindowsLocale.LooksLikeAccessDenied(eventLog.Message)
                   || (eventLog.InnerException is Win32Exception win32 && win32.NativeErrorCode == 5);
        }

        return false;
    }

    internal static string? BuildXPath(EventLogQueryOptions options)
    {
        var clauses = new List<string>();
        if (options.EventIds is { Count: > 0 })
        {
            var ids = string.Join(" or ", options.EventIds.Select(id => $"EventID={id}"));
            clauses.Add($"({ids})");
        }

        if (options.TimeRanges is { Count: > 0 } ranges)
        {
            clauses.Add(BuildTimeRangeClause(ranges));
        }
        else
        {
            if (options.FromUtc is { } from)
            {
                clauses.Add($"TimeCreated[@SystemTime>='{from:yyyy-MM-ddTHH:mm:ss.fffZ}']");
            }

            if (options.ToUtc is { } to)
            {
                clauses.Add($"TimeCreated[@SystemTime<='{to:yyyy-MM-ddTHH:mm:ss.fffZ}']");
            }
        }

        if (clauses.Count == 0)
        {
            return null;
        }

        var builder = new StringBuilder("*[System[");
        builder.Append(string.Join(" and ", clauses));
        builder.Append("]]");
        return builder.ToString();
    }

    private static string BuildTimeRangeClause(IReadOnlyList<TimeRange> ranges)
    {
        var parts = ranges.Select(range =>
            $"(TimeCreated[@SystemTime>='{range.FromUtc:yyyy-MM-ddTHH:mm:ss.fffZ}'] and TimeCreated[@SystemTime<='{range.ToUtc:yyyy-MM-ddTHH:mm:ss.fffZ}'])");
        var joined = string.Join(" or ", parts);
        return ranges.Count == 1 ? joined : $"({joined})";
    }

    private static bool Matches(EventRecord record, EventLogQueryOptions options)
    {
        try
        {
            if (options.EventIds is { Count: > 0 } && !options.EventIds.Contains(record.Id))
            {
                return false;
            }

            var created = record.TimeCreated?.ToUniversalTime();
            if (options.TimeRanges is { Count: > 0 } ranges)
            {
                if (created is { } instant && !ranges.Any(range => instant >= range.FromUtc && instant <= range.ToUtc))
                {
                    return false;
                }
            }
            else
            {
                if (options.FromUtc is { } from && created is { } c1 && c1 < from)
                {
                    return false;
                }

                if (options.ToUtc is { } to && created is { } c2 && c2 > to)
                {
                    return false;
                }
            }
        }
        catch
        {
            return true;
        }

        return true;
    }
}
