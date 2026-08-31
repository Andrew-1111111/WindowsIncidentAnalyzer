using Spectre.Console;
using WindowsIncidentAnalyzer.Models;

namespace WindowsIncidentAnalyzer.Services;

public static class ConsolePresenter
{
    private const int DefaultContentWidth = 100;

    public static Color SeverityColor(DetectionSeverity severity) => severity switch
    {
        DetectionSeverity.Critical => Color.Red,
        DetectionSeverity.High => Color.Orange1,
        DetectionSeverity.Medium => Color.Yellow,
        DetectionSeverity.Low => Color.DeepSkyBlue1,
        _ => Color.Grey
    };

    public static void Events(IReadOnlyList<WindowsEvent> events)
    {
        var table = new Table().Border(TableBorder.Rounded);
        table.AddColumn("Time UTC");
        table.AddColumn("Host");
        table.AddColumn("ID");
        table.AddColumn("User");
        table.AddColumn("Process");
        table.AddColumn("IP");
        table.AddColumn("Log");
        foreach (var evt in events)
        {
            table.AddRow(
                evt.TimeCreatedUtc.ToString("yyyy-MM-dd HH:mm:ss"),
                Cell(evt.ComputerName),
                evt.EventId.ToString(),
                Cell(evt.TargetUserName ?? evt.User),
                Cell(evt.ProcessName),
                Cell(evt.SourceIpAddress ?? evt.DestinationIpAddress),
                Cell(evt.LogName));
        }

        AnsiConsole.Write(table);
        AnsiConsole.MarkupLine($"[grey]{events.Count} row(s)[/]");
    }

    public static void Timeline(IReadOnlyList<TimelineItem> items)
    {
        var table = new Table()
            .Border(TableBorder.Rounded)
            .ShowRowSeparators();
        table.AddColumn("Timestamp UTC");
        table.AddColumn("Host");
        table.AddColumn("Event ID");
        table.AddColumn("Source");
        table.AddColumn("User");
        table.AddColumn("Process");
        table.AddColumn("IP");
        table.AddColumn("Description");
        table.AddColumn("Severity");
        foreach (var item in items)
        {
            table.AddRow(
                item.TimestampUtc.ToString("yyyy-MM-dd HH:mm:ss"),
                Cell(item.Host),
                item.EventId.ToString(),
                Cell(item.Source),
                Cell(item.User),
                Cell(item.Process),
                Cell(item.Ip),
                Cell(item.Description, 60),
                $"[{SeverityColor(item.Severity).ToMarkup()}]{item.Severity}[/]");
        }

        AnsiConsole.Write(table);
    }

    public static void Findings(IReadOnlyList<SecurityFinding> findings, int totalCount = 0)
    {
        if (findings.Count == 0)
        {
            AnsiConsole.MarkupLine("[grey]No findings.[/]");
            return;
        }

        var total = totalCount > 0 ? totalCount : findings.Count;
        WriteSectionHeader($"Findings ({findings.Count:N0} of {total:N0})");

        for (var i = 0; i < findings.Count; i++)
        {
            WriteFindingEntry(findings[i]);
            if (i < findings.Count - 1)
            {
                WriteFindingSeparator();
            }
        }
    }

    public static void AnalysisResults(InvestigationSummary summary, int maxFindings = 50)
    {
        Summary(summary);

        if (summary.IocMatches.Count > 0)
        {
            AnsiConsole.MarkupLine($"[bold]IOC matches:[/] {summary.IocMatches.Count:N0}");
        }

        if (summary.Findings.Count == 0)
        {
            AnsiConsole.MarkupLine("[grey]No detection findings in the selected time range.[/]");
        }
        else
        {
            var ordered = summary.Findings
                .OrderByDescending(f => f.Severity)
                .ThenBy(f => f.TimeUtc)
                .ToList();

            AnsiConsole.WriteLine();
            Findings(ordered.Take(maxFindings).ToList(), ordered.Count);

            if (ordered.Count > maxFindings)
            {
                AnsiConsole.MarkupLine($"[grey]... and {ordered.Count - maxFindings:N0} more. Use export for the full report.[/]");
            }
        }

        if (summary.Correlations.Count > 0)
        {
            AnsiConsole.WriteLine();
            Correlations(summary.Correlations.Take(10).ToList(), summary.Correlations.Count);
        }
    }

    public static void Correlations(IReadOnlyList<EventCorrelation> correlations, int totalCount = 0)
    {
        var total = totalCount > 0 ? totalCount : correlations.Count;
        WriteSectionHeader($"Correlated chains ({correlations.Count:N0} of {total:N0})");

        foreach (var chain in correlations)
        {
            var sev = SeverityTag(chain.Severity);
            AnsiConsole.MarkupLine(
                $"{sev} [grey]{chain.TimeUtc:yyyy-MM-dd HH:mm:ss}[/] [cyan]{Cell(chain.Scenario)}[/]");
            AnsiConsole.MarkupLine($"      {Cell(chain.Title, ContentWidth() - 6)}");
            if (!string.IsNullOrWhiteSpace(chain.User))
            {
                AnsiConsole.MarkupLine($"      [grey]user={Cell(chain.User)}[/]");
            }
        }
    }

    public static void FindingDetail(SecurityFinding finding)
    {
        var ctx = finding.Context;
        var panel = new Panel(
            $"""
            [bold]{Cell(finding.Title)}[/]
            Rule: {Cell(finding.RuleName)} ({Cell(ctx.RuleId)})
            Severity: {finding.Severity} | Category: {Cell(ctx.Category)}
            Time UTC: {finding.TimeUtc:yyyy-MM-dd HH:mm:ss}

            [bold]Event[/]
            Event ID: {ctx.EventId} | Record ID: {ctx.EventRecordId}
            Provider: {Cell(ctx.Provider)} | Channel: {Cell(ctx.Channel)}

            [bold]Host / User[/]
            Host: {Cell(ctx.Host)} | Domain: {Cell(ctx.Domain)}
            User: {Cell(ctx.User)} | SID: {Cell(ctx.UserSid)} | Logon ID: {Cell(ctx.LogonId)}

            [bold]Process[/]
            PID: {ctx.ProcessId} | PPID: {ctx.ParentProcessId}
            Image: {Cell(ctx.Image)}
            CommandLine: {Cell(ctx.CommandLine)}
            Parent Image: {Cell(ctx.ParentImage)}
            Parent CommandLine: {Cell(ctx.ParentCommandLine)}

            [bold]Network[/]
            Source: {Cell(ctx.SourceIp)}:{ctx.SourcePort}
            Destination: {Cell(ctx.DestinationIp)}:{ctx.DestinationPort}

            [bold]Sigma[/]
            Sigma ID: {Cell(ctx.SigmaId)} | Status: {Cell(ctx.SigmaStatus)}
            MITRE: {Cell(ctx.MitreTactic)} / {Cell(ctx.MitreTechnique)}
            Matched Selection: {Cell(ctx.MatchedSelection)}
            Matched Fields: {Cell(string.Join(", ", ctx.MatchedFields))}
            Matched Values: {Cell(string.Join(" | ", ctx.MatchedValues))}
            Condition: {Cell(ctx.Condition)}
            Reason: {Cell(ctx.Reason)}

            [bold]Details[/]
            {Cell(finding.Description)}
            {Cell(finding.Details)}
            """)
        {
            Header = new PanelHeader("Finding Detail"),
            Border = BoxBorder.Rounded
        };

        AnsiConsole.Write(panel);
    }

    public static void IocMatches(IReadOnlyList<IocMatch> matches)
    {
        var table = new Table().Border(TableBorder.Rounded);
        table.AddColumn("IOC Type");
        table.AddColumn("IOC Value");
        table.AddColumn("Event ID");
        table.AddColumn("Timestamp");
        table.AddColumn("Host");
        table.AddColumn("Process");
        table.AddColumn("User");
        foreach (var m in matches)
        {
            table.AddRow(
                Cell(m.IocType),
                Cell(m.IocValue, 40),
                m.EventId.ToString(),
                m.TimestampUtc.ToString("yyyy-MM-dd HH:mm:ss"),
                Cell(m.Host),
                Cell(m.RelatedProcess),
                Cell(m.RelatedUser));
        }

        AnsiConsole.Write(table);
    }

    public static void Summary(InvestigationSummary summary)
    {
        var panel = new Panel(
            $"""
            Events analyzed: [bold]{summary.EventsAnalyzed:N0}[/]

            Findings:
              Critical: {summary.CriticalCount,6:N0}
              High:     {summary.HighCount,6:N0}
              Medium:   {summary.MediumCount,6:N0}
              Low:      {summary.LowCount,6:N0}
              Info:     {summary.InfoCount,6:N0}

            IOC matches:    {summary.IocMatches.Count,6:N0}
            Correlations:   {summary.Correlations.Count,6:N0}

            Top suspicious users:
            {FormatList(summary.TopSuspiciousUsers)}

            Top suspicious IPs:
            {FormatList(summary.TopSuspiciousIps)}
            """)
        {
            Header = new PanelHeader("Investigation Summary"),
            Border = BoxBorder.Rounded
        };
        AnsiConsole.Write(panel);
    }

    public static void Stats(StatisticsResult stats)
    {
        AnsiConsole.MarkupLine("[bold]Top Event IDs[/]");
        WritePairs(stats.EventIdCounts.OrderByDescending(p => p.Value).Select(p => ($"{p.Key}", p.Value)));
        AnsiConsole.WriteLine();
        AnsiConsole.MarkupLine("[bold]Top users[/]");
        WritePairs(stats.UserCounts.Select(p => (p.Key, p.Value)));
        AnsiConsole.WriteLine();
        AnsiConsole.MarkupLine("[bold]Top processes[/]");
        WritePairs(stats.ProcessCounts.Select(p => (p.Key, p.Value)));
        AnsiConsole.WriteLine();
        AnsiConsole.MarkupLine("[bold]Top source IPs[/]");
        WritePairs(stats.SourceIpCounts.Select(p => (p.Key, p.Value)));
        AnsiConsole.WriteLine();
        AnsiConsole.MarkupLine("[bold]Events by hour (UTC)[/]");
        WritePairs(stats.EventsByHour.OrderBy(p => p.Key).Select(p => ($"{p.Key:00}:00", p.Value)));
        AnsiConsole.WriteLine();
        AnsiConsole.MarkupLine("[bold]Findings by severity[/]");
        WritePairs(stats.FindingsBySeverity.OrderByDescending(p => p.Key).Select(p => (p.Key.ToString(), p.Value)));
    }

    private static void WriteFindingEntry(SecurityFinding finding)
    {
        var ctx = finding.Context;
        var sev = SeverityTag(finding.Severity);
        var eventId = ctx.EventId?.ToString() ?? "-";

        AnsiConsole.MarkupLine(
            $"{sev} [grey]{finding.TimeUtc:yyyy-MM-dd HH:mm:ss}[/] [yellow]evt {eventId}[/] [cyan]{Cell(finding.RuleName)}[/]");
        AnsiConsole.MarkupLine($"      {Cell(finding.Title, ContentWidth() - 6)}");

        var contextLine = BuildContextLine(ctx, finding);
        if (!string.IsNullOrWhiteSpace(contextLine))
        {
            AnsiConsole.MarkupLine($"      [grey]{Cell(contextLine, ContentWidth() - 6)}[/]");
        }

        if (ctx.CategoryMatchesEvent == false)
        {
            AnsiConsole.MarkupLine(
                $"      [red]category mismatch:[/] rule={Cell(ctx.Category)} event={Cell(ctx.EventType ?? "unknown")}");
        }

        if (ctx.SeverityMatchesEvent == false)
        {
            var requested = ctx.RequestedSeverity?.ToString() ?? finding.Severity.ToString();
            AnsiConsole.MarkupLine(
                $"      [red]severity adjusted:[/] {Cell(requested)}→{Cell(finding.Severity.ToString())} (event evt {ctx.EventId})");
        }

        if (finding.Severity is DetectionSeverity.Critical or DetectionSeverity.High)
        {
            var detail = FirstNonEmpty(ctx.Reason, ctx.CommandLine, finding.Description);
            if (!string.IsNullOrWhiteSpace(detail))
            {
                AnsiConsole.MarkupLine($"      [grey]{Cell(TruncPlain(detail, ContentWidth() - 6), ContentWidth() - 6)}[/]");
            }
        }
    }

    private static void WriteFindingSeparator()
    {
        var width = Math.Max(40, Math.Min(ContentWidth(), 80));
        AnsiConsole.MarkupLine($"[grey]{new string('_', width)}[/]");
    }

    private static string BuildContextLine(FindingContext ctx, SecurityFinding finding)
    {
        var parts = new List<string>();
        var host = ctx.Host ?? finding.ComputerName;
        var user = ctx.User ?? finding.User;
        var process = ctx.ProcessName ?? ctx.Image ?? finding.ProcessName;
        var ip = ctx.SourceIp ?? finding.SourceIpAddress;
        var eventType = ctx.EventType;

        if (!string.IsNullOrWhiteSpace(eventType))
        {
            parts.Add($"type={eventType}");
        }

        if (!string.IsNullOrWhiteSpace(host))
        {
            parts.Add($"host={host}");
        }

        if (!string.IsNullOrWhiteSpace(user))
        {
            parts.Add($"user={user}");
        }

        if (!string.IsNullOrWhiteSpace(process))
        {
            parts.Add($"proc={process}");
        }

        if (!string.IsNullOrWhiteSpace(ip))
        {
            parts.Add($"ip={ip}");
        }

        return string.Join(" | ", parts);
    }

    private static void WriteSectionHeader(string title)
    {
        var width = Math.Max(40, Math.Min(ContentWidth(), 80));
        var line = new string('─', width);
        AnsiConsole.MarkupLine($"[bold]{Cell(title)}[/]");
        AnsiConsole.MarkupLine($"[grey]{line}[/]");
    }

    private static string SeverityTag(DetectionSeverity severity) =>
        $"[{SeverityColor(severity).ToMarkup()}]{AbbreviateSeverity(severity),-4}[/]";

    private static void WritePairs(IEnumerable<(string Key, int Value)> pairs)
    {
        var table = new Table().HideHeaders().Border(TableBorder.None);
        table.AddColumn(new TableColumn("name").NoWrap());
        table.AddColumn(new TableColumn("count").RightAligned().NoWrap());
        foreach (var (key, value) in pairs)
        {
            table.AddRow(Cell(key), value.ToString("N0"));
        }

        AnsiConsole.Write(table);
    }

    private static string FormatList(IReadOnlyList<string> values) =>
        values.Count == 0 ? "  (none)" : string.Join(Environment.NewLine, values.Select(v => "  " + Cell(v)));

    private static string AbbreviateSeverity(DetectionSeverity severity) => severity switch
    {
        DetectionSeverity.Critical => "CRIT",
        DetectionSeverity.High => "HIGH",
        DetectionSeverity.Medium => "MED",
        DetectionSeverity.Low => "LOW",
        _ => "INFO"
    };

    private static string? FirstNonEmpty(params string?[] values)
    {
        foreach (var value in values)
        {
            if (!string.IsNullOrWhiteSpace(value))
            {
                return value;
            }
        }

        return null;
    }

    private static string TruncPlain(string? value, int max)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return string.Empty;
        }

        return value.Length <= max ? value : value[..max] + "...";
    }

    private static string Cell(string? value, int? max = null)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return string.Empty;
        }

        var limit = max ?? ContentWidth();
        var text = value.ReplaceLineEndings(" ").Trim();
        if (text.Length > limit)
        {
            text = text[..limit] + "...";
        }

        return Markup.Escape(text);
    }

    private static int ContentWidth()
    {
        try
        {
            var width = Console.WindowWidth;
            if (width > 40)
            {
                return width - 2;
            }
        }
        catch
        {
            // Console width may be unavailable in redirected output.
        }

        return DefaultContentWidth;
    }
}
