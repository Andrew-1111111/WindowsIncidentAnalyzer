using System.CommandLine;
using Microsoft.Extensions.Options;
using WindowsIncidentAnalyzer.Configuration;
using WindowsIncidentAnalyzer.Infrastructure;
using WindowsIncidentAnalyzer.Models;

namespace WindowsIncidentAnalyzer.Commands;

public static class SharedCliOptions
{
    public static Option<string?> Log { get; } = new("--log")
    {
        Description = "Event log alias or full channel name (Security/Безопасность, System/Система, Application/Приложение, Sysmon, PowerShell)."
    };

    public static Option<int?> Hours { get; } = new("--hours")
    {
        Description = "Look back this many hours from now (UTC)."
    };

    public static Option<string?> From { get; } = new("--from")
    {
        Description = "Start of time range (UTC if 'Z' suffix, otherwise converted to UTC). Example: \"2026-08-01 00:00:00\"."
    };

    public static Option<string?> To { get; } = new("--to")
    {
        Description = "End of time range. Example: \"2026-08-02 00:00:00\"."
    };

    public static Option<string?> Date { get; } = new("--date")
    {
        Description = "Local calendar date or dates. Examples: 2026-08-29  or  2026-08-28,2026-08-29  or  2026-08-01..2026-08-07."
    };

    public static Option<string?> EventId { get; } = new("--event-id")
    {
        Description = "Event ID or comma-separated list. Example: 4624,4625,4688."
    };

    public static Option<string?> User { get; } = new("--user")
    {
        Description = "Filter by account name (subject or target)."
    };

    public static Option<string?> Ip { get; } = new("--ip")
    {
        Description = "Filter by source or destination IP address."
    };

    public static Option<string?> Process { get; } = new("--process")
    {
        Description = "Filter by process name, path, or command line."
    };

    public static Option<string?> Keyword { get; } = new("--keyword")
    {
        Description = "Full-text keyword matched against normalized fields, Raw XML, and properties."
    };

    public static Option<int?> Limit { get; } = new("--limit")
    {
        Description = "Maximum number of events to process."
    };

    public static Option<int?> BatchSize { get; } = new("--batch-size")
    {
        Description = "SQLite insert batch size during collection."
    };

    public static Option<string?> Evtx { get; } = new("--evtx")
    {
        Description = "Read a saved EVTX file in read-only mode instead of a live channel."
    };

    public static Option<string?> Export { get; } = new("--export")
    {
        Description = "Export path. Format is inferred from the extension (.csv, .json, .html)."
    };

    public static Option<string> Format { get; } = new("--format")
    {
        Description = "Export format: csv, json, or html."
    };

    public static EventQueryFilter BuildFilter(
        ParseResult parse,
        AnalyzerOptions analyzer,
        bool defaultHoursWhenMissing)
    {
        DateTime? from;
        DateTime? to;
        IReadOnlyList<TimeRange>? timeRanges = null;

        var dateValue = parse.GetValue(Date);
        if (!string.IsNullOrWhiteSpace(dateValue))
        {
            timeRanges = DateRangeParser.Parse(dateValue);
            from = timeRanges.Min(r => r.FromUtc);
            to = timeRanges.Max(r => r.ToUtc);
        }
        else
        {
            var hours = parse.GetValue(Hours);
            from = DateTimeParser.Parse(parse.GetValue(From));
            to = DateTimeParser.Parse(parse.GetValue(To));
            if (hours is > 0)
            {
                to ??= DateTime.UtcNow;
                from ??= to.Value.AddHours(-hours.Value);
            }
            else if (defaultHoursWhenMissing && from is null && to is null)
            {
                to = DateTime.UtcNow;
                from = to.Value.AddHours(-Math.Max(1, analyzer.Collection.DefaultHours));
            }
        }

        var limit = parse.GetValue(Limit) ?? (defaultHoursWhenMissing ? analyzer.Collection.DefaultLimit : 1000);

        return new EventQueryFilter
        {
            EventIds = EventIdParser.Parse(parse.GetValue(EventId)),
            User = parse.GetValue(User),
            IpAddress = parse.GetValue(Ip),
            ProcessName = parse.GetValue(Process),
            Keyword = parse.GetValue(Keyword),
            FromUtc = from,
            ToUtc = to,
            TimeRanges = timeRanges,
            Limit = limit
        };
    }
}
