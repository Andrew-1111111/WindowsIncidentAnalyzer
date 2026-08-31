using System.CommandLine;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Spectre.Console;
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

                var db = services.GetRequiredService<SqliteDatabase>();
                var count = await services.GetRequiredService<IEventIngestionService>().CollectAsync(request, token);

                AnsiConsole.WriteLine();
                AnsiConsole.Write(new Rule("[green]Collect complete[/]").RuleStyle("grey"));
                AnsiConsole.MarkupLine($"Rows changed  : [bold]{count:N0}[/] (new or more complete events)");
                AnsiConsole.MarkupLine($"Database      : {Markup.Escape(db.DatabasePath)}");
                if (request.TimeRanges is { Count: > 0 } dates)
                {
                    AnsiConsole.MarkupLine($"Dates         : {Markup.Escape(DateRangeParser.DescribeLocal(dates))} (local)");
                    AnsiConsole.MarkupLine($"Time range    : {request.FromUtc:yyyy-MM-dd HH:mm} UTC → {request.ToUtc:yyyy-MM-dd HH:mm} UTC");
                }
                else if (request.FromUtc is { } from && request.ToUtc is { } to)
                {
                    AnsiConsole.MarkupLine($"Time range    : {from:yyyy-MM-dd HH:mm} UTC → {to:yyyy-MM-dd HH:mm} UTC");
                }
                else
                {
                    AnsiConsole.MarkupLine("Time range    : all recorded events");
                }

                if (request.Limit is { } limit)
                {
                    AnsiConsole.MarkupLine($"Limit         : {limit:N0}");
                }

                foreach (var log in request.AccessDeniedLogs.Distinct())
                {
                    AnsiConsole.MarkupLine($"Skipped       : [yellow]{Markup.Escape(log)}[/] (access denied — run as Administrator)");
                }

                foreach (var log in request.MissingLogs.Distinct())
                {
                    AnsiConsole.MarkupLine($"Skipped       : [yellow]{Markup.Escape(log)}[/] (not installed or not found)");
                }

                if (string.IsNullOrWhiteSpace(request.LogName) && string.IsNullOrWhiteSpace(request.EvtxPath))
                {
                    AnsiConsole.MarkupLine("[grey]Sources: Security, System, Application, PowerShell, Sysmon.[/]");
                }

                if (count == 0 && request.AccessDeniedLogs.Count > 0 && string.IsNullOrWhiteSpace(request.EvtxPath))
                {
                    AnsiConsole.MarkupLine("[grey]Tip: collect --log Application   or   collect --evtx C:\\Evidence\\Security.evtx[/]");
                }

                AnsiConsole.WriteLine();
            }, ct);
        });

        return command;
    }
}
