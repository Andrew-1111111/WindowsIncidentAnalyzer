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
        ExportPath.EnsureDirectory(full);

        var html = Build(data);
        await File.WriteAllTextAsync(full, html, Encoding.UTF8, cancellationToken);
    }

    public static string Build(InvestigationExport data)
    {
        var events = ExportRowBuilder.BuildEventMap(data);
        var criticalRows = ExportRowBuilder.BuildFindingRows(
                data.Findings
                    .Where(f => f.Severity is DetectionSeverity.Critical or DetectionSeverity.High)
                    .OrderByDescending(f => f.Severity)
                    .ThenBy(f => f.TimeUtc)
                    .ToList(),
                events)
            .ToList();
        var allFindingRows = ExportRowBuilder.BuildFindingRows(
                data.Findings.OrderByDescending(f => f.Severity).ThenBy(f => f.TimeUtc).ToList(),
                events)
            .ToList();

        var sb = new StringBuilder();
        sb.AppendLine("<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">");
        sb.AppendLine($"<title>{Enc(data.Title)}</title>");
        sb.AppendLine(HtmlExportStyles.DocumentHead);

        sb.AppendLine($"<h1>{Enc(data.Title)}</h1>");
        sb.AppendLine(
            $"<div class=\"meta\">Generated (UTC): {data.GeneratedUtc:yyyy-MM-dd HH:mm:ss}<br>" +
            $"Events: {data.Statistics.TotalEvents:N0} | Findings: {data.Statistics.TotalFindings:N0} | " +
            $"IOC matches: {data.IocMatches.Count:N0} | CVE matches: {data.CveMatches.Count:N0} | Correlations: {data.Correlations.Count:N0} | " +
            $"Timeline items: {data.Timeline.Count:N0} | Related events: {data.Events.Count:N0}</div>");

        AppendSeverityCards(sb, data.Statistics);

        sb.AppendLine("<section><h2>Critical and High findings</h2>");
        AppendFindingsTable(sb, criticalRows);
        sb.AppendLine("</section>");

        sb.AppendLine("<section><h2>All findings</h2>");
        AppendFindingsTable(sb, allFindingRows);
        sb.AppendLine("</section>");

        sb.AppendLine("<section><h2>IOC matches</h2>");
        AppendIocTable(sb, ExportRowBuilder.BuildIocRows(data.IocMatches).ToList());
        sb.AppendLine("</section>");

        sb.AppendLine("<section><h2>CVE matches</h2>");
        AppendCveTable(sb, ExportRowBuilder.BuildCveRows(data.CveMatches).ToList());
        sb.AppendLine("</section>");

        sb.AppendLine("<section><h2>Correlations</h2>");
        AppendCorrelationTable(sb, ExportRowBuilder.BuildCorrelationRows(data.Correlations).ToList());
        sb.AppendLine("</section>");

        sb.AppendLine("<section><h2>Timeline</h2>");
        AppendTimelineTable(sb, ExportRowBuilder.BuildTimelineRows(data.Timeline).ToList());
        sb.AppendLine("</section>");

        sb.AppendLine("<section><h2>Related events</h2>");
        AppendEventsTable(sb, ExportRowBuilder.BuildEventRows(data.Events).ToList());
        sb.AppendLine("</section>");

        AppendStatisticsSection(sb, data.Statistics);
        sb.AppendLine("</body></html>");
        return sb.ToString();
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

    private static void AppendFindingsTable(StringBuilder sb, IReadOnlyList<FindingCsvRow> rows)
    {
        AppendTableStart(sb);
        sb.AppendLine("""
            <tr>
            <th class="col-sev">Severity</th><th class="col-id">Finding ID</th><th class="col-rule">Rule</th><th class="col-short">Rule ID</th><th class="col-desc">Rule Title</th>
            <th class="col-desc">Title</th><th class="col-short">Category</th><th class="col-short">Event Type</th>
            <th class="col-short">Cat match</th><th class="col-short">Sev match</th><th class="col-sev">Requested sev</th>
            <th class="col-time">Time UTC</th><th class="col-time">Created UTC</th>
            <th class="col-host">Host</th><th class="col-short">Domain</th><th class="col-user">User</th><th class="col-short">User SID</th><th class="col-short">Logon ID</th>
            <th class="col-num">Event ID</th><th class="col-num">Record ID</th><th class="col-path">Provider</th><th class="col-short">Channel</th>
            <th class="col-num">PID</th><th class="col-num">PPID</th><th class="col-host">Process</th><th class="col-path">Image</th>
            <th class="col-cmd">Command Line</th><th class="col-path">Parent Image</th><th class="col-cmd">Parent Command Line</th>
            <th class="col-path">Working Dir</th><th class="col-short">Integrity</th><th class="col-short">Elevation</th>
            <th class="col-ip">Source IP</th><th class="col-num">Src port</th><th class="col-ip">Dest IP</th><th class="col-num">Dst port</th>
            <th class="col-path">File Path</th><th class="col-short">SHA256</th><th class="col-short">MD5</th><th class="col-short">Signer</th><th class="col-short">Original name</th>
            <th class="col-short">Sigma ID</th><th class="col-short">Sigma status</th>
            <th class="col-mitre">MITRE Tactic</th><th class="col-mitre">MITRE Technique</th><th class="col-mitre">Technique name</th><th class="col-mitre">Tactic name</th><th class="col-path">MITRE URL</th><th class="col-mitre">MITRE tags</th>
            <th class="col-short">Selection</th><th class="col-desc">Matched fields</th><th class="col-desc">Matched values</th><th class="col-short">Condition</th>
            <th class="col-desc">Reason</th><th class="col-desc">Description</th><th class="col-desc">Details</th><th class="col-short">Related IDs</th>
            <th class="col-xml">Raw Event</th><th class="col-xml">Raw XML</th>
            </tr>
            """);
        AppendTableBody(sb);

        foreach (var r in rows)
        {
            sb.AppendLine(
                $"<tr><td class=\"col-sev {Enc(r.Severity)}\">{Cell(r.Severity)}</td><td class=\"col-id\">{r.FindingId}</td>" +
                $"<td class=\"col-rule\">{Cell(r.RuleName)}</td><td class=\"mono col-short\">{Cell(r.RuleId)}</td><td class=\"col-desc\">{Cell(r.RuleTitle)}</td>" +
                $"<td class=\"col-desc\">{Cell(r.Title)}</td><td class=\"col-short\">{Cell(r.Category)}</td><td class=\"col-short\">{Cell(r.EventType)}</td>" +
                $"<td class=\"col-short\">{Cell(r.CategoryMatchesEvent)}</td><td class=\"col-short\">{Cell(r.SeverityMatchesEvent)}</td><td class=\"col-sev\">{Cell(r.RequestedSeverity)}</td>" +
                $"<td class=\"mono col-time\">{Cell(r.TimeUtc)}</td><td class=\"mono col-time\">{Cell(r.CreatedUtc)}</td>" +
                $"<td class=\"col-host\">{Cell(r.Host)}</td><td class=\"col-short\">{Cell(r.Domain)}</td><td class=\"col-user\">{Cell(r.User)}</td>" +
                $"<td class=\"mono col-short\">{Cell(r.UserSid)}</td><td class=\"mono col-short\">{Cell(r.LogonId)}</td>" +
                $"<td class=\"col-num\">{Num(r.EventId)}</td><td class=\"col-num\">{Num(r.EventRecordId)}</td>" +
                $"<td class=\"col-path\">{Cell(r.Provider)}</td><td class=\"col-short\">{Cell(r.Channel)}</td>" +
                $"<td class=\"col-num\">{Num(r.ProcessId)}</td><td class=\"col-num\">{Num(r.ParentProcessId)}</td>" +
                $"<td class=\"col-host\">{Cell(r.ProcessName)}</td><td class=\"mono col-path\">{Cell(r.Image)}</td>" +
                $"<td class=\"mono col-cmd\">{Cell(r.CommandLine)}</td><td class=\"mono col-path\">{Cell(r.ParentImage)}</td><td class=\"mono col-cmd\">{Cell(r.ParentCommandLine)}</td>" +
                $"<td class=\"mono col-path\">{Cell(r.WorkingDirectory)}</td><td class=\"col-short\">{Cell(r.IntegrityLevel)}</td><td class=\"col-short\">{Cell(r.ElevationType)}</td>" +
                $"<td class=\"mono col-ip\">{Cell(r.SourceIp)}</td><td class=\"col-num\">{Num(r.SourcePort)}</td><td class=\"mono col-ip\">{Cell(r.DestinationIp)}</td><td class=\"col-num\">{Num(r.DestinationPort)}</td>" +
                $"<td class=\"mono col-path\">{Cell(r.FilePath)}</td><td class=\"mono col-short\">{Cell(r.Sha256)}</td><td class=\"mono col-short\">{Cell(r.Md5)}</td>" +
                $"<td class=\"col-short\">{Cell(r.Signer)}</td><td class=\"col-short\">{Cell(r.OriginalFileName)}</td>" +
                $"<td class=\"mono col-short\">{Cell(r.SigmaId)}</td><td class=\"col-short\">{Cell(r.SigmaStatus)}</td>" +
                $"<td class=\"col-mitre\">{Cell(r.MitreTactic)}</td><td class=\"col-mitre\">{Cell(r.MitreTechnique)}</td>" +
                $"<td class=\"col-mitre\">{Cell(r.MitreTechniqueName)}</td><td class=\"col-mitre\">{Cell(r.MitreTacticName)}</td>" +
                $"<td class=\"mono col-path\">{Cell(r.MitreUrl)}</td><td class=\"col-mitre\">{Cell(r.MitreTags)}</td>" +
                $"<td class=\"col-short\">{Cell(r.MatchedSelection)}</td><td class=\"col-desc\">{Cell(r.MatchedFields)}</td><td class=\"mono col-desc\">{Cell(r.MatchedValues)}</td>" +
                $"<td class=\"col-short\">{Cell(r.Condition)}</td><td class=\"col-desc\">{Cell(r.Reason)}</td><td class=\"col-desc\">{Cell(r.Description)}</td>" +
                $"<td class=\"mono col-desc\">{Cell(r.Details)}</td><td class=\"mono col-short\">{Cell(r.RelatedEventRowIds)}</td>" +
                $"<td class=\"col-xml\">{CollapsibleText("Raw Event JSON", r.RawEvent)}</td><td class=\"col-xml\">{CollapsibleXml(r.RawXml)}</td></tr>");
        }

        AppendEmptyRow(sb, rows.Count, 59);
        AppendTableEnd(sb);
    }

    private static void AppendIocTable(StringBuilder sb, IReadOnlyList<IocCsvRow> rows)
    {
        AppendTableStart(sb);
        sb.AppendLine(
            "<tr><th class=\"col-short\">Type</th><th class=\"col-path\">Value</th><th class=\"col-num\">Event ID</th><th class=\"col-id\">Event Row ID</th>" +
            "<th class=\"col-time\">Time UTC</th><th class=\"col-host\">Host</th><th class=\"col-host\">Process</th><th class=\"col-user\">User</th><th class=\"col-short\">Matched field</th></tr>");
        AppendTableBody(sb);
        foreach (var m in rows)
        {
            sb.AppendLine(
                $"<tr><td class=\"col-short\">{Cell(m.IocType)}</td><td class=\"mono col-path\">{Cell(m.IocValue)}</td><td class=\"col-num\">{m.EventId}</td><td class=\"col-id\">{m.EventRowId}</td>" +
                $"<td class=\"mono col-time\">{Cell(m.TimestampUtc)}</td><td class=\"col-host\">{Cell(m.Host)}</td><td class=\"col-host\">{Cell(m.RelatedProcess)}</td>" +
                $"<td class=\"col-user\">{Cell(m.RelatedUser)}</td><td class=\"col-short\">{Cell(m.MatchedField)}</td></tr>");
        }

        AppendEmptyRow(sb, rows.Count, 9);
        AppendTableEnd(sb);
    }

    private static void AppendCveTable(StringBuilder sb, IReadOnlyList<CveCsvRow> rows)
    {
        AppendTableStart(sb);
        sb.AppendLine(
            "<tr><th class=\"col-short\">CVE ID</th><th class=\"col-desc\">Vulnerability</th><th class=\"col-desc\">Description</th><th class=\"col-short\">Vendor</th><th class=\"col-short\">Product</th>" +
            "<th class=\"col-short\">Ransomware</th><th class=\"col-num\">Event ID</th><th class=\"col-id\">Event Row ID</th><th class=\"col-time\">Time UTC</th>" +
            "<th class=\"col-host\">Host</th><th class=\"col-host\">Process</th><th class=\"col-user\">User</th><th class=\"col-short\">Matched field</th></tr>");
        AppendTableBody(sb);
        foreach (var m in rows)
        {
            sb.AppendLine(
                $"<tr><td class=\"mono col-short\">{Cell(m.CveId)}</td><td class=\"col-desc\">{Cell(m.VulnerabilityName)}</td><td class=\"col-desc\">{Cell(m.ShortDescription)}</td>" +
                $"<td class=\"col-short\">{Cell(m.VendorProject)}</td><td class=\"col-short\">{Cell(m.Product)}</td><td class=\"col-short\">{Cell(m.KnownRansomwareUse)}</td>" +
                $"<td class=\"col-num\">{m.EventId}</td><td class=\"col-id\">{m.EventRowId}</td><td class=\"mono col-time\">{Cell(m.TimestampUtc)}</td>" +
                $"<td class=\"col-host\">{Cell(m.Host)}</td><td class=\"col-host\">{Cell(m.RelatedProcess)}</td><td class=\"col-user\">{Cell(m.RelatedUser)}</td>" +
                $"<td class=\"col-short\">{Cell(m.MatchedField)}</td></tr>");
        }

        AppendEmptyRow(sb, rows.Count, 13);
        AppendTableEnd(sb);
    }

    private static void AppendCorrelationTable(StringBuilder sb, IReadOnlyList<CorrelationCsvRow> rows)
    {
        AppendTableStart(sb);
        sb.AppendLine(
            "<tr><th class=\"col-id\">ID</th><th class=\"col-sev\">Severity</th><th class=\"col-short\">Scenario</th><th class=\"col-desc\">Title</th>" +
            "<th class=\"col-time\">Time UTC</th><th class=\"col-time\">Created UTC</th><th class=\"col-user\">User</th><th class=\"col-host\">Host</th>" +
            "<th class=\"col-ip\">Source IP</th><th class=\"col-desc\">Interpretation</th><th class=\"col-desc\">Details</th><th class=\"col-short\">Related IDs</th></tr>");
        AppendTableBody(sb);
        foreach (var c in rows)
        {
            sb.AppendLine(
                $"<tr><td class=\"col-id\">{c.CorrelationId}</td><td class=\"col-sev {Enc(c.Severity)}\">{Cell(c.Severity)}</td><td class=\"col-short\">{Cell(c.Scenario)}</td>" +
                $"<td class=\"col-desc\">{Cell(c.Title)}</td><td class=\"mono col-time\">{Cell(c.TimeUtc)}</td><td class=\"mono col-time\">{Cell(c.CreatedUtc)}</td>" +
                $"<td class=\"col-user\">{Cell(c.User)}</td><td class=\"col-host\">{Cell(c.ComputerName)}</td><td class=\"mono col-ip\">{Cell(c.SourceIpAddress)}</td>" +
                $"<td class=\"col-desc\">{Cell(c.Interpretation)}</td><td class=\"mono col-desc\">{Cell(c.Details)}</td><td class=\"mono col-short\">{Cell(c.RelatedEventRowIds)}</td></tr>");
        }

        AppendEmptyRow(sb, rows.Count, 12);
        AppendTableEnd(sb);
    }

    private static void AppendTimelineTable(StringBuilder sb, IReadOnlyList<TimelineCsvRow> rows)
    {
        AppendTableStart(sb);
        sb.AppendLine(
            "<tr><th class=\"col-time\">Time UTC</th><th class=\"col-id\">Event Row ID</th><th class=\"col-host\">Host</th><th class=\"col-num\">Event ID</th>" +
            "<th class=\"col-short\">Source</th><th class=\"col-user\">User</th><th class=\"col-host\">Process</th><th class=\"col-ip\">IP</th>" +
            "<th class=\"col-desc\">Description</th><th class=\"col-sev\">Severity</th></tr>");
        AppendTableBody(sb);
        foreach (var t in rows)
        {
            sb.AppendLine(
                $"<tr><td class=\"mono col-time\">{Cell(t.TimestampUtc)}</td><td class=\"col-id\">{t.EventRowId}</td><td class=\"col-host\">{Cell(t.Host)}</td>" +
                $"<td class=\"col-num\">{t.EventId}</td><td class=\"col-short\">{Cell(t.Source)}</td><td class=\"col-user\">{Cell(t.User)}</td>" +
                $"<td class=\"col-host\">{Cell(t.Process)}</td><td class=\"mono col-ip\">{Cell(t.Ip)}</td><td class=\"col-desc\">{Cell(t.Description)}</td>" +
                $"<td class=\"col-sev {Enc(t.Severity)}\">{Cell(t.Severity)}</td></tr>");
        }

        AppendEmptyRow(sb, rows.Count, 10);
        AppendTableEnd(sb);
    }

    private static void AppendEventsTable(StringBuilder sb, IReadOnlyList<EventCsvRow> rows)
    {
        AppendTableStart(sb);
        sb.AppendLine("""
            <tr>
            <th class="col-id">Row ID</th><th class="col-time">Time UTC</th><th class="col-host">Host</th><th class="col-short">Log</th><th class="col-path">Provider</th>
            <th class="col-num">Event ID</th><th class="col-num">Record ID</th><th class="col-short">Level</th>
            <th class="col-user">User</th><th class="col-short">Domain</th><th class="col-user">Target user</th><th class="col-short">Target domain</th>
            <th class="col-host">Process</th><th class="col-path">Image</th><th class="col-num">PID</th><th class="col-host">Parent</th><th class="col-num">PPID</th>
            <th class="col-cmd">Parent cmd</th><th class="col-cmd">Command line</th>
            <th class="col-ip">Source IP</th><th class="col-ip">Dest IP</th><th class="col-num">Src port</th><th class="col-num">Dst port</th>
            <th class="col-host">Workstation</th><th class="col-num">Logon</th>
            <th class="col-desc">Script block</th><th class="col-short">Script hash</th><th class="col-path">Hashes</th>
            <th class="col-short">Process GUID</th><th class="col-short">Parent GUID</th>
            <th class="col-path">DNS</th><th class="col-path">Task</th><th class="col-path">Service</th>
            <th class="col-desc">Properties</th><th class="col-xml">Raw XML</th>
            </tr>
            """);
        AppendTableBody(sb);

        foreach (var evt in rows)
        {
            sb.AppendLine(
                $"<tr><td class=\"col-id\">{evt.EventRowId}</td><td class=\"mono col-time\">{Cell(evt.TimeCreatedUtc)}</td><td class=\"col-host\">{Cell(evt.ComputerName)}</td>" +
                $"<td class=\"col-short\">{Cell(evt.LogName)}</td><td class=\"col-path\">{Cell(evt.ProviderName)}</td><td class=\"col-num\">{evt.EventId}</td>" +
                $"<td class=\"col-num\">{Num(evt.EventRecordId)}</td><td class=\"col-short\">{Cell(evt.Level)}</td>" +
                $"<td class=\"col-user\">{Cell(evt.User)}</td><td class=\"col-short\">{Cell(evt.Domain)}</td><td class=\"col-user\">{Cell(evt.TargetUserName)}</td>" +
                $"<td class=\"col-short\">{Cell(evt.TargetDomainName)}</td><td class=\"col-host\">{Cell(evt.ProcessName)}</td><td class=\"mono col-path\">{Cell(evt.ProcessPath)}</td>" +
                $"<td class=\"col-num\">{Num(evt.ProcessId)}</td><td class=\"col-host\">{Cell(evt.ParentProcessName)}</td><td class=\"col-num\">{Num(evt.ParentProcessId)}</td>" +
                $"<td class=\"mono col-cmd\">{Cell(evt.ParentCommandLine)}</td><td class=\"mono col-cmd\">{Cell(evt.CommandLine)}</td>" +
                $"<td class=\"mono col-ip\">{Cell(evt.SourceIpAddress)}</td><td class=\"mono col-ip\">{Cell(evt.DestinationIpAddress)}</td>" +
                $"<td class=\"col-num\">{Num(evt.SourcePort)}</td><td class=\"col-num\">{Num(evt.DestinationPort)}</td>" +
                $"<td class=\"col-host\">{Cell(evt.WorkstationName)}</td><td class=\"col-num\">{Num(evt.LogonType)}</td>" +
                $"<td class=\"mono col-desc\">{LongCell(evt.ScriptBlock, "Script block")}</td><td class=\"mono col-short\">{Cell(evt.ScriptBlockHash)}</td>" +
                $"<td class=\"mono col-path\">{Cell(evt.Hashes)}</td><td class=\"mono col-short\">{Cell(evt.ProcessGuid)}</td><td class=\"mono col-short\">{Cell(evt.ParentProcessGuid)}</td>" +
                $"<td class=\"col-path\">{Cell(evt.QueryName)}</td><td class=\"col-path\">{Cell(evt.TaskName)}</td><td class=\"col-path\">{Cell(evt.ServiceName)}</td>" +
                $"<td class=\"mono col-desc\">{LongCell(evt.PropertiesJson, "Properties JSON")}</td><td class=\"col-xml\">{CollapsibleXml(evt.RawXml)}</td></tr>");
        }

        AppendEmptyRow(sb, rows.Count, 35);
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
        sb.AppendLine("<tr><th class=\"col-path\">Name</th><th class=\"col-num\">Count</th></tr>");
        AppendTableBody(sb);
        foreach (var (key, value) in rows)
        {
            sb.AppendLine($"<tr><td class=\"col-path\">{Cell(key)}</td><td class=\"col-num\">{value:N0}</td></tr>");
        }

        AppendTableEnd(sb);
    }

    private static void AppendTableStart(StringBuilder sb) => sb.AppendLine("<div class=\"table-wrap\"><table class=\"data\"><thead>");

    private static void AppendTableBody(StringBuilder sb) => sb.AppendLine("</thead><tbody>");

    private static void AppendTableEnd(StringBuilder sb) => sb.AppendLine("</tbody></table></div>");

    private static void AppendEmptyRow(StringBuilder sb, int count, int colspan)
    {
        if (count == 0)
        {
            sb.AppendLine($"<tr><td colspan=\"{colspan}\" class=\"empty\">None.</td></tr>");
        }
    }

    private static string Cell(string? value) =>
        string.IsNullOrWhiteSpace(value) ? "<span class=\"empty\">—</span>" : Enc(value);

    /// <summary>
    /// Shows short values inline; long values keep the full payload inside a collapsible block.
    /// </summary>
    private static string LongCell(string? value, string label, int inlineMax = 400)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return "<span class=\"empty\">—</span>";
        }

        return value.Length <= inlineMax
            ? Enc(value)
            : CollapsibleText(label, value);
    }

    private static string Num(int? value) => value.HasValue ? value.Value.ToString() : "<span class=\"empty\">—</span>";

    private static string Num(long? value) => value.HasValue ? value.Value.ToString() : "<span class=\"empty\">—</span>";

    private static string CollapsibleXml(string? rawXml) => CollapsibleText("Raw XML", rawXml);

    private static string CollapsibleText(string label, string? content)
    {
        if (string.IsNullOrWhiteSpace(content))
        {
            return "<span class=\"empty\">—</span>";
        }

        var length = content.Length;
        var summary = length == 1 ? $"{label} (1 char)" : $"{label} ({length:N0} chars)";
        return $"<details class=\"xml-fold\"><summary>{Enc(summary)}</summary><pre class=\"mono\">{Enc(content)}</pre></details>";
    }

    private static string Enc(string? value) => WebUtility.HtmlEncode(value ?? string.Empty);
}
