using System.Net;
using System.Text;
using WindowsIncidentAnalyzer.Models;

namespace WindowsIncidentAnalyzer.Exporters;

public sealed class HtmlExporter : IExporter
{
    public string Format => "html";

    public async Task ExportAsync(InvestigationExport data, string path, CancellationToken cancellationToken)
    {
        var full = Path.GetFullPath(path);
        var directory = Path.GetDirectoryName(full);
        if (!string.IsNullOrEmpty(directory))
        {
            Directory.CreateDirectory(directory);
        }

        var html = Build(data);
        await File.WriteAllTextAsync(full, html, Encoding.UTF8, cancellationToken);
    }

    public static string Build(InvestigationExport data)
    {
        var sb = new StringBuilder();
        sb.AppendLine("<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">");
        sb.AppendLine($"<title>{Enc(data.Title)}</title>");
        sb.AppendLine("<style>");
        sb.AppendLine("""
            :root { color-scheme: dark; }
            body { font-family: Segoe UI, Tahoma, sans-serif; background:#0f1419; color:#e6edf3; margin:0; padding:24px; }
            h1,h2,h3 { color:#f0f6fc; }
            h1 { font-size:1.6rem; margin-bottom:0.2rem; }
            .meta { color:#8b949e; margin-bottom:24px; line-height:1.6; }
            .cards { display:flex; gap:12px; flex-wrap:wrap; margin:16px 0 28px; }
            .card { background:#161b22; border:1px solid #30363d; border-radius:8px; padding:12px 16px; min-width:120px; }
            .card strong { display:block; font-size:1.4rem; }
            table { width:100%; border-collapse:collapse; margin:12px 0 28px; font-size:0.85rem; }
            th,td { border-bottom:1px solid #30363d; padding:6px 8px; text-align:left; vertical-align:top; }
            th { background:#161b22; color:#8b949e; font-weight:600; position:sticky; top:0; }
            tr:hover td { background:#1c2330; }
            .Critical { color:#ff7b72; font-weight:700; }
            .High { color:#ffa198; font-weight:700; }
            .Medium { color:#d29922; }
            .Low { color:#79c0ff; }
            .Info { color:#8b949e; }
            .mono { font-family: Consolas, Cascadia Mono, monospace; font-size:0.8rem; word-break:break-all; }
            section { margin-bottom:32px; }
            .filter-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(220px,1fr)); gap:8px 16px; margin:12px 0 24px; }
            .filter-item { background:#161b22; border:1px solid #30363d; border-radius:6px; padding:8px 10px; }
            .filter-item span { color:#8b949e; display:block; font-size:0.75rem; }
            .table-wrap { overflow:auto; max-height:70vh; border:1px solid #30363d; border-radius:8px; }
            details.xml-fold { max-width:480px; }
            details.xml-fold > summary { cursor:pointer; color:#58a6ff; user-select:none; list-style-position:outside; }
            details.xml-fold > summary:hover { text-decoration:underline; }
            details.xml-fold > pre { margin:8px 0 0; padding:8px; background:#0d1117; border:1px solid #30363d; border-radius:6px;
                max-height:320px; overflow:auto; white-space:pre-wrap; word-break:break-all; font-size:0.75rem; }
            </style></head><body>
            """);

        sb.AppendLine($"<h1>{Enc(data.Title)}</h1>");
        sb.AppendLine(
            $"<div class=\"meta\">Generated (UTC): {data.GeneratedUtc:yyyy-MM-dd HH:mm:ss}<br>" +
            $"Events: {data.Statistics.TotalEvents:N0} | Findings: {data.Statistics.TotalFindings:N0} | " +
            $"IOC matches: {data.IocMatches.Count:N0} | Correlations: {data.Correlations.Count:N0} | " +
            $"Timeline items: {data.Timeline.Count:N0} | Related events: {data.Events.Count:N0}</div>");

        AppendFilterSection(sb, data.Filter);
        AppendSeverityCards(sb, data.Statistics);

        sb.AppendLine("<section><h2>Critical and High findings</h2>");
        AppendFindingsTable(sb, data.Findings
            .Where(f => f.Severity is DetectionSeverity.Critical or DetectionSeverity.High)
            .OrderByDescending(f => f.Severity)
            .ThenBy(f => f.TimeUtc)
            .ToList());
        sb.AppendLine("</section>");

        sb.AppendLine("<section><h2>All findings</h2>");
        AppendFindingsTable(sb, data.Findings.OrderByDescending(f => f.Severity).ThenBy(f => f.TimeUtc).ToList());
        sb.AppendLine("</section>");

        sb.AppendLine("<section><h2>IOC matches</h2>");
        AppendTableStart(sb);
        sb.AppendLine("<tr><th>Type</th><th>Value</th><th>Event ID</th><th>Event Row ID</th><th>Timestamp UTC</th><th>Host</th><th>Process</th><th>User</th><th>Matched field</th></tr>");
        foreach (var m in data.IocMatches)
        {
            sb.AppendLine(
                $"<tr><td>{Enc(m.IocType)}</td><td class=\"mono\">{Enc(m.IocValue)}</td><td>{m.EventId}</td><td>{m.EventRowId}</td>" +
                $"<td class=\"mono\">{m.TimestampUtc:u}</td><td>{Enc(m.Host)}</td><td>{Enc(m.RelatedProcess)}</td><td>{Enc(m.RelatedUser)}</td><td>{Enc(m.MatchedField)}</td></tr>");
        }

        AppendEmptyRow(sb, data.IocMatches.Count, 9);
        AppendTableEnd(sb);
        sb.AppendLine("</section>");

        sb.AppendLine("<section><h2>Correlations</h2>");
        AppendTableStart(sb);
        sb.AppendLine("<tr><th>ID</th><th>Severity</th><th>Scenario</th><th>Title</th><th>Time UTC</th><th>Created UTC</th><th>User</th><th>Host</th><th>Source IP</th><th>Interpretation</th><th>Details</th><th>Related event IDs</th></tr>");
        foreach (var c in data.Correlations)
        {
            sb.AppendLine(
                $"<tr><td>{c.Id}</td><td class=\"{c.Severity}\">{c.Severity}</td><td>{Enc(c.Scenario)}</td><td>{Enc(c.Title)}</td>" +
                $"<td class=\"mono\">{c.TimeUtc:u}</td><td class=\"mono\">{c.CreatedUtc:u}</td><td>{Enc(c.User)}</td><td>{Enc(c.ComputerName)}</td>" +
                $"<td class=\"mono\">{Enc(c.SourceIpAddress)}</td><td>{Enc(c.Interpretation)}</td><td class=\"mono\">{Enc(c.Details)}</td>" +
                $"<td class=\"mono\">{Enc(string.Join(", ", c.RelatedEventRowIds))}</td></tr>");
        }

        AppendEmptyRow(sb, data.Correlations.Count, 12);
        AppendTableEnd(sb);
        sb.AppendLine("</section>");

        sb.AppendLine("<section><h2>Timeline</h2>");
        AppendTableStart(sb);
        sb.AppendLine("<tr><th>Timestamp UTC</th><th>Event Row ID</th><th>Host</th><th>Event ID</th><th>Source</th><th>User</th><th>Process</th><th>IP</th><th>Description</th><th>Severity</th></tr>");
        foreach (var t in data.Timeline)
        {
            sb.AppendLine(
                $"<tr><td class=\"mono\">{t.TimestampUtc:u}</td><td>{t.EventRowId}</td><td>{Enc(t.Host)}</td><td>{t.EventId}</td>" +
                $"<td>{Enc(t.Source)}</td><td>{Enc(t.User)}</td><td>{Enc(t.Process)}</td><td class=\"mono\">{Enc(t.Ip)}</td>" +
                $"<td>{Enc(t.Description)}</td><td class=\"{t.Severity}\">{t.Severity}</td></tr>");
        }

        AppendEmptyRow(sb, data.Timeline.Count, 10);
        AppendTableEnd(sb);
        sb.AppendLine("</section>");

        sb.AppendLine("<section><h2>Related events</h2>");
        AppendEventsTable(sb, data.Events);
        sb.AppendLine("</section>");

        AppendStatisticsSection(sb, data.Statistics);
        sb.AppendLine("</body></html>");
        return sb.ToString();
    }

    private static void AppendFilterSection(StringBuilder sb, EventQueryFilter? filter)
    {
        sb.AppendLine("<section><h2>Investigation filter</h2><div class=\"filter-grid\">");
        if (filter == null)
        {
            sb.AppendLine("<div class=\"filter-item\">No filter metadata.</div></div></section>");
            return;
        }

        AppendFilterItem(sb, "User", filter.User);
        AppendFilterItem(sb, "IP address", filter.IpAddress);
        AppendFilterItem(sb, "Process", filter.ProcessName);
        AppendFilterItem(sb, "Keyword", filter.Keyword);
        AppendFilterItem(sb, "Computer", filter.ComputerName);
        AppendFilterItem(sb, "Log", filter.LogName);
        AppendFilterItem(sb, "From UTC", filter.FromUtc?.ToString("u"));
        AppendFilterItem(sb, "To UTC", filter.ToUtc?.ToString("u"));
        AppendFilterItem(sb, "Limit", filter.Limit.ToString());
        AppendFilterItem(sb, "Event IDs", filter.EventIds is { Count: > 0 } ids ? string.Join(", ", ids) : null);
        sb.AppendLine("</div></section>");
    }

    private static void AppendFilterItem(StringBuilder sb, string label, string? value)
    {
        sb.AppendLine($"<div class=\"filter-item\"><span>{Enc(label)}</span>{Enc(string.IsNullOrWhiteSpace(value) ? "—" : value)}</div>");
    }

    private static void AppendSeverityCards(StringBuilder sb, StatisticsResult stats)
    {
        sb.AppendLine("<div class=\"cards\">");
        foreach (var sev in new[] { DetectionSeverity.Critical, DetectionSeverity.High, DetectionSeverity.Medium, DetectionSeverity.Low, DetectionSeverity.Info })
        {
            stats.FindingsBySeverity.TryGetValue(sev, out var count);
            sb.AppendLine($"<div class=\"card\"><span class=\"{sev}\">{sev}</span><strong>{count}</strong></div>");
        }

        sb.AppendLine("</div>");
    }

    private static void AppendFindingsTable(StringBuilder sb, IReadOnlyList<SecurityFinding> findings)
    {
        AppendTableStart(sb);
        sb.AppendLine(
            "<tr><th>ID</th><th>Severity</th><th>Time UTC</th><th>Rule</th><th>Rule ID</th><th>Title</th><th>Category</th><th>Event type</th>" +
            "<th>Event ID</th><th>Host</th><th>User</th><th>Process</th><th>Command line</th><th>Source IP</th><th>Dest IP</th>" +
            "<th>Sigma ID</th><th>MITRE</th><th>Matched fields</th><th>Reason</th><th>Description</th><th>Details</th><th>Related IDs</th><th>Raw XML</th></tr>");

        foreach (var f in findings)
        {
            var ctx = f.Context;
            var mitre = string.Join(", ", new[] { ctx.MitreTactic, ctx.MitreTechnique }.Where(v => !string.IsNullOrWhiteSpace(v)));
            sb.AppendLine(
                $"<tr><td>{f.Id}</td><td class=\"{f.Severity}\">{f.Severity}</td><td class=\"mono\">{f.TimeUtc:u}</td><td>{Enc(f.RuleName)}</td><td class=\"mono\">{Enc(ctx.RuleId)}</td>" +
                $"<td>{Enc(f.Title)}</td><td>{Enc(ctx.Category)}</td><td>{Enc(ctx.EventType)}</td><td>{ctx.EventId}</td><td>{Enc(ctx.Host ?? f.ComputerName)}</td>" +
                $"<td>{Enc(ctx.User ?? f.User)}</td><td>{Enc(ctx.ProcessName ?? ctx.Image ?? f.ProcessName)}</td><td class=\"mono\">{Enc(ctx.CommandLine)}</td>" +
                $"<td class=\"mono\">{Enc(ctx.SourceIp ?? f.SourceIpAddress)}</td><td class=\"mono\">{Enc(ctx.DestinationIp)}</td><td class=\"mono\">{Enc(ctx.SigmaId)}</td>" +
                $"<td>{Enc(mitre)}</td><td>{Enc(string.Join(" | ", ctx.MatchedFields))}</td><td>{Enc(ctx.Reason)}</td><td>{Enc(f.Description)}</td>" +
                $"<td class=\"mono\">{Enc(f.Details)}</td><td class=\"mono\">{Enc(string.Join(", ", f.RelatedEventRowIds))}</td><td>{CollapsibleXml(ctx.RawXml)}</td></tr>");
        }

        AppendEmptyRow(sb, findings.Count, 23);
        AppendTableEnd(sb);
    }

    private static void AppendEventsTable(StringBuilder sb, IReadOnlyList<WindowsEvent> events)
    {
        AppendTableStart(sb);
        sb.AppendLine(
            "<tr><th>Row ID</th><th>Time UTC</th><th>Host</th><th>Log</th><th>Provider</th><th>Event ID</th><th>Record ID</th>" +
            "<th>User</th><th>Target user</th><th>Process</th><th>Image</th><th>PID</th><th>Parent</th><th>PPID</th>" +
            "<th>Command line</th><th>Parent cmd</th><th>Source IP</th><th>Dest IP</th><th>Ports</th><th>Logon</th>" +
            "<th>Script block</th><th>DNS/Task/Service</th><th>Properties</th><th>Raw XML</th></tr>");

        foreach (var evt in events)
        {
            var ports = $"{evt.SourcePort?.ToString() ?? "-"} → {evt.DestinationPort?.ToString() ?? "-"}";
            var extras = string.Join(" | ", new[]
            {
                string.IsNullOrWhiteSpace(evt.QueryName) ? null : $"dns={evt.QueryName}",
                string.IsNullOrWhiteSpace(evt.TaskName) ? null : $"task={evt.TaskName}",
                string.IsNullOrWhiteSpace(evt.ServiceName) ? null : $"svc={evt.ServiceName}"
            }.Where(v => v != null));

            sb.AppendLine(
                $"<tr><td>{evt.Id}</td><td class=\"mono\">{evt.TimeCreatedUtc:u}</td><td>{Enc(evt.ComputerName)}</td><td>{Enc(evt.LogName)}</td><td>{Enc(evt.ProviderName)}</td>" +
                $"<td>{evt.EventId}</td><td>{evt.EventRecordId}</td><td>{Enc(evt.User)}</td><td>{Enc(evt.TargetUserName)}</td><td>{Enc(evt.ProcessName)}</td>" +
                $"<td class=\"mono\">{Enc(evt.ProcessPath)}</td><td>{evt.ProcessId}</td><td>{Enc(evt.ParentProcessName)}</td><td>{evt.ParentProcessId}</td>" +
                $"<td class=\"mono\">{Enc(evt.CommandLine)}</td><td class=\"mono\">{Enc(evt.ParentCommandLine)}</td><td class=\"mono\">{Enc(evt.SourceIpAddress)}</td>" +
                $"<td class=\"mono\">{Enc(evt.DestinationIpAddress)}</td><td class=\"mono\">{Enc(ports)}</td><td>{evt.LogonType}</td>" +
                $"<td class=\"mono\">{Enc(Truncate(evt.ScriptBlock, 1000))}</td><td>{Enc(extras)}</td><td class=\"mono\">{Enc(Truncate(string.Join("; ", evt.Properties.Select(p => $"{p.Key}={p.Value}")), 1500))}</td>" +
                $"<td>{CollapsibleXml(evt.RawXml)}</td></tr>");
        }

        AppendEmptyRow(sb, events.Count, 24);
        AppendTableEnd(sb);
    }

    private static void AppendStatisticsSection(StringBuilder sb, StatisticsResult stats)
    {
        sb.AppendLine("<section><h2>Statistics</h2>");
        AppendCountTable(sb, "Top Event IDs", stats.EventIdCounts.OrderByDescending(p => p.Value).Select(p => (p.Key.ToString(), p.Value)));
        AppendCountTable(sb, "Top users", stats.UserCounts.Select(p => (p.Key, p.Value)));
        AppendCountTable(sb, "Top processes", stats.ProcessCounts.Select(p => (p.Key, p.Value)));
        AppendCountTable(sb, "Top source IPs", stats.SourceIpCounts.Select(p => (p.Key, p.Value)));
        AppendCountTable(sb, "Events by hour (UTC)", stats.EventsByHour.OrderBy(p => p.Key).Select(p => ($"{p.Key:00}:00", p.Value)));
        sb.AppendLine("</section>");
    }

    private static void AppendCountTable(StringBuilder sb, string title, IEnumerable<(string Key, int Value)> rows)
    {
        sb.AppendLine($"<h3>{Enc(title)}</h3>");
        AppendTableStart(sb);
        sb.AppendLine("<tr><th>Name</th><th>Count</th></tr>");
        foreach (var (key, value) in rows)
        {
            sb.AppendLine($"<tr><td>{Enc(key)}</td><td>{value:N0}</td></tr>");
        }

        AppendTableEnd(sb);
    }

    private static void AppendTableStart(StringBuilder sb) => sb.AppendLine("<div class=\"table-wrap\"><table>");

    private static void AppendTableEnd(StringBuilder sb) => sb.AppendLine("</table></div>");

    private static void AppendEmptyRow(StringBuilder sb, int count, int colspan)
    {
        if (count == 0)
        {
            sb.AppendLine($"<tr><td colspan=\"{colspan}\">None.</td></tr>");
        }
    }

    private static string Truncate(string? value, int max) =>
        string.IsNullOrEmpty(value) || value.Length <= max ? value ?? string.Empty : value[..max] + "...";

    private static string CollapsibleXml(string? rawXml)
    {
        if (string.IsNullOrWhiteSpace(rawXml))
        {
            return "—";
        }

        var length = rawXml.Length;
        var summary = length == 1 ? "Raw XML (1 char)" : $"Raw XML ({length:N0} chars)";
        return $"<details class=\"xml-fold\"><summary>{Enc(summary)}</summary><pre class=\"mono\">{Enc(rawXml)}</pre></details>";
    }

    private static string Enc(string? value) => WebUtility.HtmlEncode(value ?? string.Empty);
}
