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

public sealed class EventLogQueryOptions
{
    public string? LogName { get; init; }

    public string? EvtxPath { get; init; }

    public DateTime? FromUtc { get; init; }

    public DateTime? ToUtc { get; init; }

    public IReadOnlyList<TimeRange>? TimeRanges { get; init; }

    public IReadOnlyList<int>? EventIds { get; init; }

    public int? Limit { get; init; }

    /// <summary>
    /// When true, access denied on a channel fails the command.
    /// When false (default multi-log collect), the channel is skipped.
    /// </summary>
    public bool ThrowOnAccessDenied { get; init; }

    public IList<string>? AccessDeniedLogs { get; init; }

    public IList<string>? MissingLogs { get; init; }
}

public sealed class EventLogService(
    EventXmlParser parser,
    IOptions<AnalyzerOptions> options,
    ILogger<EventLogService> logger) : IEventLogService
{
    public async IAsyncEnumerable<WindowsEvent> CollectAsync(
        EventLogQueryOptions queryOptions,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        var logs = ResolveLogs(queryOptions);
        var collection = options.Value.Collection;

        if (CollectionParallelism.ShouldUseParallel(collection, logs.Count))
        {
            logger.LogInformation(
                "Collecting {Count} event log channel(s) in parallel (workers={Workers})",
                logs.Count,
                ParallelAnalysis.ResolveMaxDegreeOfParallelism(collection));

            await foreach (var evt in CollectParallelAsync(logs, queryOptions, collection, cancellationToken))
            {
                yield return evt;
            }

            yield break;
        }

        await foreach (var evt in CollectSequentialAsync(logs, queryOptions, cancellationToken))
        {
            yield return evt;
        }
    }

    public async IAsyncEnumerable<WindowsEvent> ReadChannelAsync(
        string path,
        PathType pathType,
        EventLogQueryOptions options,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        EventLogQuery query;
        try
        {
            var xpath = BuildXPath(options);
            query = string.IsNullOrEmpty(xpath)
                ? new EventLogQuery(path, pathType)
                : new EventLogQuery(path, pathType, xpath);
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "XPath query rejected for {Path}; falling back to unfiltered read", path);
            query = new EventLogQuery(path, pathType);
        }

        EventLogReader? reader = null;
        try
        {
            reader = new EventLogReader(query);
        }
        catch (EventLogNotFoundException ex)
        {
            logger.LogWarning(ex, "Event log {Path} was not found", path);
            TrackMissingLog(options, path);
            yield break;
        }
        catch (Exception ex) when (IsAccessDenied(ex))
        {
            logger.LogWarning(ex, "Access denied to event log {Path}", path);
            TrackAccessDenied(options, path);
            if (options.ThrowOnAccessDenied)
            {
                throw new UnauthorizedAccessException(
                    $"Cannot read event log '{path}'. The Security log (and often Sysmon) require Administrator rights or membership in Event Log Readers. Other commands (search, analyze, EVTX files) do not.",
                    ex);
            }

            yield break;
        }
        catch (EventLogException ex)
        {
            logger.LogError(ex, "Cannot open event log {Path}", path);
            TrackMissingLog(options, path);
            yield break;
        }

        using (reader)
        {
            while (true)
            {
                cancellationToken.ThrowIfCancellationRequested();
                EventRecord? record = null;
                try
                {
                    record = reader.ReadEvent();
                }
                catch (EventLogException ex)
                {
                    logger.LogWarning(ex, "Skipping unreadable record in {Path}", path);
                    continue;
                }
                catch (InvalidOperationException ex)
                {
                    logger.LogWarning(ex, "Reader stopped for {Path}", path);
                    break;
                }

                if (record == null)
                {
                    break;
                }

                WindowsEvent? parsed = null;
                try
                {
                    using (record)
                    {
                        if (!Matches(record, options))
                        {
                            continue;
                        }

                        string xml;
                        try
                        {
                            xml = record.ToXml();
                        }
                        catch (Exception ex)
                        {
                            logger.LogWarning(ex, "Failed to export XML for record {Id} in {Path}", record.Id, path);
                            continue;
                        }

                        parsed = parser.Parse(xml);
                    }
                }
                catch (Exception ex)
                {
                    logger.LogWarning(ex, "Failed to normalize an event from {Path}", path);
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
        EventLogQueryOptions options,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        var yielded = 0;
        foreach (var logName in logs)
        {
            cancellationToken.ThrowIfCancellationRequested();
            await foreach (var evt in ReadChannelAsync(logName, PathType.LogName, options, cancellationToken))
            {
                yield return evt;
                yielded++;
                if (options.Limit is > 0 && yielded >= options.Limit)
                {
                    yield break;
                }
            }
        }
    }

    private async IAsyncEnumerable<WindowsEvent> CollectParallelAsync(
        IReadOnlyList<string> logs,
        EventLogQueryOptions options,
        CollectionOptions collection,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        var capacity = Math.Max(collection.DefaultBatchSize * 2, 1000);
        var channel = Channel.CreateBounded<WindowsEvent>(new BoundedChannelOptions(capacity)
        {
            FullMode = BoundedChannelFullMode.Wait,
            SingleReader = true,
            SingleWriter = false
        });

        using var stopCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var producer = ProduceChannelsAsync(logs, options, collection, channel.Writer, stopCts);

        var yielded = 0;
        try
        {
            await foreach (var evt in channel.Reader.ReadAllAsync(cancellationToken))
            {
                yielded++;
                if (options.Limit is > 0 && yielded > options.Limit)
                {
                    stopCts.Cancel();
                    break;
                }

                yield return evt;
            }
        }
        finally
        {
            await producer.ConfigureAwait(false);
        }
    }

    private async Task ProduceChannelsAsync(
        IReadOnlyList<string> logs,
        EventLogQueryOptions options,
        CollectionOptions collection,
        ChannelWriter<WindowsEvent> writer,
        CancellationTokenSource stopCts)
    {
        try
        {
            var parallelism = ParallelAnalysis.ResolveMaxDegreeOfParallelism(collection);
            await Parallel.ForEachAsync(
                logs,
                new ParallelOptions
                {
                    MaxDegreeOfParallelism = parallelism,
                    CancellationToken = stopCts.Token
                },
                async (logName, ct) =>
                {
                    await foreach (var evt in ReadChannelAsync(logName, PathType.LogName, options, ct))
                    {
                        await writer.WriteAsync(evt, ct).ConfigureAwait(false);
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

    private static List<string> ResolveLogs(EventLogQueryOptions options)
    {
        if (!string.IsNullOrWhiteSpace(options.LogName))
        {
            return [WindowsLogNames.Resolve(options.LogName)];
        }

        return WindowsLogNames.DefaultCollectionLogs.ToList();
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
