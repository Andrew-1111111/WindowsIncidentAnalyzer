namespace WindowsIncidentAnalyzer.Exporters;

internal static class HtmlExportStyles
{
    public const string DocumentHead = """
        <style>
        :root { color-scheme: dark; }
        body { font-family: Segoe UI, Tahoma, sans-serif; background:#0f1419; color:#e6edf3; margin:0; padding:24px; }
        h1,h2,h3 { color:#f0f6fc; }
        h1 { font-size:1.6rem; margin-bottom:0.2rem; }
        .meta { color:#8b949e; margin-bottom:24px; line-height:1.6; }
        .cards { display:flex; gap:12px; flex-wrap:wrap; margin:16px 0 28px; }
        .card { background:#161b22; border:1px solid #30363d; border-radius:8px; padding:12px 16px; min-width:120px; }
        .card strong { display:block; font-size:1.4rem; }
        .table-wrap { overflow:auto; max-height:70vh; border:1px solid #30363d; border-radius:8px; }
        table.data { border-collapse:collapse; margin:0; font-size:0.82rem; width:max-content; min-width:100%; }
        table.data th, table.data td { border-bottom:1px solid #30363d; padding:6px 8px; text-align:left; vertical-align:top; }
        table.data th { background:#161b22; color:#8b949e; font-weight:600; position:sticky; top:0; z-index:1; }
        table.data tr:hover td { background:#1c2330; }
        .Critical { color:#ff7b72; font-weight:700; }
        .High { color:#ffa198; font-weight:700; }
        .Medium { color:#d29922; }
        .Low { color:#79c0ff; }
        .Info { color:#8b949e; }
        .mono { font-family: Consolas, Cascadia Mono, monospace; font-size:0.78rem; }
        .col-sev { min-width:5.5rem; white-space:nowrap; }
        .col-id, .col-num { min-width:4.5rem; white-space:nowrap; }
        .col-time { min-width:11rem; max-width:11rem; white-space:nowrap; }
        .col-host, .col-user, .col-rule { min-width:9rem; max-width:14rem; overflow-wrap:anywhere; }
        .col-short { min-width:7rem; max-width:12rem; overflow-wrap:anywhere; }
        .col-ip { min-width:8.5rem; white-space:nowrap; }
        .col-path { min-width:14rem; max-width:26rem; overflow-wrap:anywhere; word-break:break-word; }
        .col-cmd { min-width:18rem; max-width:36rem; overflow-wrap:anywhere; word-break:break-word; }
        .col-desc { min-width:16rem; max-width:32rem; overflow-wrap:anywhere; word-break:break-word; }
        .col-mitre { min-width:12rem; max-width:20rem; overflow-wrap:anywhere; }
        .col-xml { min-width:9rem; }
        .empty { color:#8b949e; }
        section { margin-bottom:32px; }
        details.xml-fold { max-width:28rem; }
        details.xml-fold > summary { cursor:pointer; color:#58a6ff; user-select:none; }
        details.xml-fold > summary:hover { text-decoration:underline; }
        details.xml-fold > pre { margin:8px 0 0; padding:8px; background:#0d1117; border:1px solid #30363d; border-radius:6px;
            max-height:320px; overflow:auto; white-space:pre-wrap; word-break:break-all; font-size:0.75rem; }
        </style></head><body>
        """;
}
