using System.CommandLine;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using WindowsIncidentAnalyzer.Configuration;
using WindowsIncidentAnalyzer.Infrastructure;
using WindowsIncidentAnalyzer.Services;

namespace WindowsIncidentAnalyzer.Commands;

public static class CollectCommand
{
    public static Command Create(IServiceProvider services)
    {
        var command = new Command("collect", "Collect events from live Windows logs or a read-only EVTX file into SQLite.");
        command.Options.Add(SharedCliOptions.Log);
        command.Options.Add(SharedCliOptions.Hours);
        command.Options.Add(SharedCliOptions.From);
        command.Options.Add(SharedCliOptions.To);
        command.Options.Add(SharedCliOptions.Date);
        command.Options.Add(SharedCliOptions.EventId);
        command.Options.Add(SharedCliOptions.Limit);
        command.Options.Add(SharedCliOptions.BatchSize);
        command.Options.Add(SharedCliOptions.Evtx);

        command.SetAction(async (parse, ct) =>
        {
            var handler = services.GetRequiredService<CliErrorHandler>();
            return await handler.RunAsync(async token =>
            {
                var analyzer = services.GetRequiredService<IOptions<AnalyzerOptions>>().Value;
                var filter = SharedCliOptions.BuildFilter(parse, analyzer, defaultHoursWhenMissing: false);
                var request = new CollectRequest
                {
                    LogName = parse.GetValue(SharedCliOptions.Log),
                    EvtxPath = parse.GetValue(SharedCliOptions.Evtx),
                    FromUtc = filter.FromUtc,
                    ToUtc = filter.ToUtc,
                    TimeRanges = filter.TimeRanges,
                    EventIds = filter.EventIds is { Count: > 0 } ? filter.EventIds : null,
                    Limit = parse.GetValue(SharedCliOptions.Limit),
                    BatchSize = parse.GetValue(SharedCliOptions.BatchSize) ?? analyzer.Collection.DefaultBatchSize
                };

                var db = services.GetRequiredService<InvestigationDatabase>();
                var count = await services.GetRequiredService<IEventIngestionService>().CollectAsync(request, token);

                // Plain Console I/O — Spectre Markup/Rule hits GetBufferInfo and floods VS Output
                // with first-chance IOException under the debugger.
                WriteLine(string.Empty);
                WriteLine("Collect complete");
                WriteLine($"Rows changed  : {count:N0} (new or more complete events)");
                WriteLine($"Database      : {db.DatabasePath}");
                if (request.TimeRanges is { Count: > 0 } dates)
                {
                    WriteLine($"Dates         : {DateRangeParser.DescribeLocal(dates)} (local)");
                    WriteLine($"Time range    : {request.FromUtc:yyyy-MM-dd HH:mm} UTC → {request.ToUtc:yyyy-MM-dd HH:mm} UTC");
                }
                else if (request.FromUtc is { } from && request.ToUtc is { } to)
                {
                    WriteLine($"Time range    : {from:yyyy-MM-dd HH:mm} UTC → {to:yyyy-MM-dd HH:mm} UTC");
                }
                else
                {
                    WriteLine("Time range    : all recorded events");
                }

                if (request.Limit is { } limit)
                {
                    WriteLine($"Limit         : {limit:N0}");
                }

                foreach (var log in request.AccessDeniedLogs.Distinct())
                {
                    WriteLine($"Skipped       : {log} (access denied — run as Administrator)");
                }

                foreach (var log in request.MissingLogs.Distinct())
                {
                    WriteLine($"Skipped       : {log} (not installed or not found)");
                }

                if (string.IsNullOrWhiteSpace(request.LogName) && string.IsNullOrWhiteSpace(request.EvtxPath))
                {
                    var sources = WindowsLogCatalog.ResolveCollectionLogs(
                        request.LogName,
                        analyzer.Collection.CollectAllLogs,
                        analyzer.Collection.IncludeAnalyticDebugLogs,
                        discoverFromEvtxFiles: false);

                    if (analyzer.Collection.CollectAllLogs ||
                        WindowsLogCatalog.IsAllLogsAlias(request.LogName))
                    {
                        WriteLine($"Sources: enabled Windows event log channels ({sources.Count:N0}).");
                    }
                    else
                    {
                        WriteLine($"Sources: {string.Join(", ", sources)}.");
                    }
                }

                if (count == 0 && request.AccessDeniedLogs.Count > 0 && string.IsNullOrWhiteSpace(request.EvtxPath))
                {
                    WriteLine("Tip: collect --log Application   or   collect --evtx C:\\Evidence\\Security.evtx");
                }

                WriteLine(string.Empty);
            }, ct);
        });

        return command;
    }

    private static void WriteLine(string message)
    {
        try
        {
            Console.Out.WriteLine(message);
        }
        catch
        {
            // Ignore detached console.
        }
    }
}
