using System.Text.Json;
using WindowsIncidentAnalyzer.Models;

namespace WindowsIncidentAnalyzer.Exporters;

internal static class ExportRowBuilder
{
    public static IReadOnlyDictionary<long, WindowsEvent> BuildEventMap(InvestigationExport data) =>
        data.Events.ToDictionary(evt => evt.Id);

    public static IEnumerable<FindingCsvRow> BuildFindingRows(
        IReadOnlyList<SecurityFinding> findings,
        IReadOnlyDictionary<long, WindowsEvent> events)
    {
        foreach (var finding in findings)
        {
            events.TryGetValue(finding.RelatedEventRowIds.FirstOrDefault(), out var evt);
            var ctx = finding.Context;

            yield return new FindingCsvRow
            {
                Severity = CsvExportFormatting.Cell(finding.Severity.ToString()),
                FindingId = finding.Id,
                RuleName = CsvExportFormatting.Cell(finding.RuleName),
                RuleId = CsvExportFormatting.Cell(ctx.RuleId),
                RuleTitle = CsvExportFormatting.Cell(ctx.RuleTitle),
                Title = CsvExportFormatting.Cell(finding.Title),
                Category = CsvExportFormatting.Cell(ctx.Category),
                EventType = CsvExportFormatting.Cell(ctx.EventType),
                CategoryMatchesEvent = CsvExportFormatting.FormatNullableBool(ctx.CategoryMatchesEvent),
                SeverityMatchesEvent = CsvExportFormatting.FormatNullableBool(ctx.SeverityMatchesEvent),
                RequestedSeverity = CsvExportFormatting.Cell(ctx.RequestedSeverity?.ToString()),
                TimeUtc = CsvExportFormatting.FormatUtc(ctx.TimestampUtc ?? finding.TimeUtc),
                CreatedUtc = CsvExportFormatting.FormatUtc(finding.CreatedUtc),
                Host = CsvExportFormatting.Cell(ctx.Host ?? finding.ComputerName ?? evt?.ComputerName),
                Domain = CsvExportFormatting.Cell(ctx.Domain ?? evt?.TargetDomainName ?? evt?.Domain),
                User = CsvExportFormatting.Cell(ctx.User ?? finding.User ?? evt?.TargetUserName ?? evt?.User),
                UserSid = CsvExportFormatting.Cell(ctx.UserSid),
                LogonId = CsvExportFormatting.Cell(ctx.LogonId),
                EventId = ctx.EventId ?? evt?.EventId,
                EventRecordId = ctx.EventRecordId ?? evt?.EventRecordId,
                Provider = CsvExportFormatting.Cell(ctx.Provider ?? evt?.ProviderName),
                Channel = CsvExportFormatting.Cell(ctx.Channel ?? evt?.LogName),
                ProcessId = ctx.ProcessId ?? evt?.ProcessId,
                ParentProcessId = ctx.ParentProcessId ?? evt?.ParentProcessId,
                ProcessName = CsvExportFormatting.Cell(ctx.ProcessName ?? finding.ProcessName ?? evt?.ProcessName),
                Image = CsvExportFormatting.Cell(ctx.Image ?? evt?.ProcessPath ?? evt?.ProcessName),
                CommandLine = CsvExportFormatting.Cell(ctx.CommandLine ?? evt?.CommandLine),
                ParentImage = CsvExportFormatting.Cell(ctx.ParentImage ?? evt?.ParentProcessName),
                ParentCommandLine = CsvExportFormatting.Cell(ctx.ParentCommandLine ?? evt?.ParentCommandLine),
                WorkingDirectory = CsvExportFormatting.Cell(ctx.WorkingDirectory),
                IntegrityLevel = CsvExportFormatting.Cell(ctx.IntegrityLevel),
                ElevationType = CsvExportFormatting.Cell(ctx.ElevationType),
                SourceIp = CsvExportFormatting.Cell(ctx.SourceIp ?? finding.SourceIpAddress ?? evt?.SourceIpAddress),
                SourcePort = ctx.SourcePort ?? evt?.SourcePort,
                DestinationIp = CsvExportFormatting.Cell(ctx.DestinationIp ?? evt?.DestinationIpAddress),
                DestinationPort = ctx.DestinationPort ?? evt?.DestinationPort,
                FilePath = CsvExportFormatting.Cell(ctx.FilePath),
                Sha256 = CsvExportFormatting.Cell(ctx.Sha256),
                Md5 = CsvExportFormatting.Cell(ctx.Md5),
                Signer = CsvExportFormatting.Cell(ctx.Signer),
                OriginalFileName = CsvExportFormatting.Cell(ctx.OriginalFileName),
                SigmaId = CsvExportFormatting.Cell(ctx.SigmaId),
                SigmaStatus = CsvExportFormatting.Cell(ctx.SigmaStatus),
                MitreTactic = CsvExportFormatting.Cell(ctx.MitreTactic),
                MitreTechnique = CsvExportFormatting.Cell(ctx.MitreTechnique),
                MitreTags = CsvExportFormatting.FormatList(ctx.MitreTags),
                MatchedSelection = CsvExportFormatting.Cell(ctx.MatchedSelection),
                MatchedFields = CsvExportFormatting.FormatList(ctx.MatchedFields),
                MatchedValues = CsvExportFormatting.FormatList(ctx.MatchedValues),
                Condition = CsvExportFormatting.Cell(ctx.Condition),
                Reason = CsvExportFormatting.Cell(ctx.Reason),
                Description = CsvExportFormatting.Cell(finding.Description),
                Details = CsvExportFormatting.Cell(finding.Details),
                RelatedEventRowIds = CsvExportFormatting.FormatIds(finding.RelatedEventRowIds),
                RawEvent = CsvExportFormatting.Cell(ctx.RawEvent),
                RawXml = CsvExportFormatting.Cell(ctx.RawXml ?? evt?.RawXml)
            };
        }
    }

    public static IEnumerable<TimelineCsvRow> BuildTimelineRows(IReadOnlyList<TimelineItem> timeline) =>
        timeline.Select(t => new TimelineCsvRow
        {
            TimestampUtc = CsvExportFormatting.FormatUtc(t.TimestampUtc),
            EventRowId = t.EventRowId,
            Host = CsvExportFormatting.Cell(t.Host),
            EventId = t.EventId,
            Source = CsvExportFormatting.Cell(t.Source),
            User = CsvExportFormatting.Cell(t.User),
            Process = CsvExportFormatting.Cell(t.Process),
            Ip = CsvExportFormatting.Cell(t.Ip),
            Description = CsvExportFormatting.Cell(t.Description),
            Severity = CsvExportFormatting.Cell(t.Severity.ToString())
        });

    public static IEnumerable<IocCsvRow> BuildIocRows(IReadOnlyList<IocMatch> matches) =>
        matches.Select(m => new IocCsvRow
        {
            IocType = CsvExportFormatting.Cell(m.IocType),
            IocValue = CsvExportFormatting.Cell(m.IocValue),
            EventId = m.EventId,
            EventRowId = m.EventRowId,
            TimestampUtc = CsvExportFormatting.FormatUtc(m.TimestampUtc),
            Host = CsvExportFormatting.Cell(m.Host),
            RelatedProcess = CsvExportFormatting.Cell(m.RelatedProcess),
            RelatedUser = CsvExportFormatting.Cell(m.RelatedUser),
            MatchedField = CsvExportFormatting.Cell(m.MatchedField)
        });

    public static IEnumerable<CorrelationCsvRow> BuildCorrelationRows(IReadOnlyList<EventCorrelation> correlations) =>
        correlations.Select(c => new CorrelationCsvRow
        {
            CorrelationId = c.Id,
            Severity = CsvExportFormatting.Cell(c.Severity.ToString()),
            Scenario = CsvExportFormatting.Cell(c.Scenario),
            Title = CsvExportFormatting.Cell(c.Title),
            TimeUtc = CsvExportFormatting.FormatUtc(c.TimeUtc),
            CreatedUtc = CsvExportFormatting.FormatUtc(c.CreatedUtc),
            User = CsvExportFormatting.Cell(c.User),
            SourceIpAddress = CsvExportFormatting.Cell(c.SourceIpAddress),
            ComputerName = CsvExportFormatting.Cell(c.ComputerName),
            Interpretation = CsvExportFormatting.Cell(c.Interpretation),
            Details = CsvExportFormatting.Cell(c.Details),
            RelatedEventRowIds = CsvExportFormatting.FormatIds(c.RelatedEventRowIds)
        });

    public static IEnumerable<EventCsvRow> BuildEventRows(IReadOnlyList<WindowsEvent> events) =>
        events.Select(evt => new EventCsvRow
        {
            EventRowId = evt.Id,
            TimeCreatedUtc = CsvExportFormatting.FormatUtc(evt.TimeCreatedUtc),
            ComputerName = CsvExportFormatting.Cell(evt.ComputerName),
            LogName = CsvExportFormatting.Cell(evt.LogName),
            ProviderName = CsvExportFormatting.Cell(evt.ProviderName),
            EventId = evt.EventId,
            EventRecordId = evt.EventRecordId,
            Level = CsvExportFormatting.Cell(evt.Level),
            User = CsvExportFormatting.Cell(evt.User),
            Domain = CsvExportFormatting.Cell(evt.Domain),
            TargetUserName = CsvExportFormatting.Cell(evt.TargetUserName),
            TargetDomainName = CsvExportFormatting.Cell(evt.TargetDomainName),
            ProcessName = CsvExportFormatting.Cell(evt.ProcessName),
            ProcessPath = CsvExportFormatting.Cell(evt.ProcessPath),
            ProcessId = evt.ProcessId,
            ParentProcessName = CsvExportFormatting.Cell(evt.ParentProcessName),
            ParentProcessId = evt.ParentProcessId,
            ParentCommandLine = CsvExportFormatting.Cell(evt.ParentCommandLine),
            CommandLine = CsvExportFormatting.Cell(evt.CommandLine),
            SourceIpAddress = CsvExportFormatting.Cell(evt.SourceIpAddress),
            DestinationIpAddress = CsvExportFormatting.Cell(evt.DestinationIpAddress),
            SourcePort = evt.SourcePort,
            DestinationPort = evt.DestinationPort,
            WorkstationName = CsvExportFormatting.Cell(evt.WorkstationName),
            LogonType = evt.LogonType,
            ScriptBlock = CsvExportFormatting.Cell(evt.ScriptBlock),
            ScriptBlockHash = CsvExportFormatting.Cell(evt.ScriptBlockHash),
            Hashes = CsvExportFormatting.Cell(evt.Hashes),
            ProcessGuid = CsvExportFormatting.Cell(evt.ProcessGuid),
            ParentProcessGuid = CsvExportFormatting.Cell(evt.ParentProcessGuid),
            QueryName = CsvExportFormatting.Cell(evt.QueryName),
            TaskName = CsvExportFormatting.Cell(evt.TaskName),
            ServiceName = CsvExportFormatting.Cell(evt.ServiceName),
            PropertiesJson = CsvExportFormatting.FormatProperties(evt.Properties),
            RawXml = CsvExportFormatting.Cell(evt.RawXml)
        });

    public static IEnumerable<StatisticsCsvRow> BuildStatisticsRows(StatisticsResult stats, EventQueryFilter? filter)
    {
        yield return new StatisticsCsvRow { Section = "Summary", Key = "TotalEvents", Value = stats.TotalEvents.ToString() };
        yield return new StatisticsCsvRow { Section = "Summary", Key = "TotalFindings", Value = stats.TotalFindings.ToString() };

        if (filter != null)
        {
            yield return new StatisticsCsvRow { Section = "Filter", Key = "User", Value = CsvExportFormatting.Cell(filter.User) };
            yield return new StatisticsCsvRow { Section = "Filter", Key = "IpAddress", Value = CsvExportFormatting.Cell(filter.IpAddress) };
            yield return new StatisticsCsvRow { Section = "Filter", Key = "ProcessName", Value = CsvExportFormatting.Cell(filter.ProcessName) };
            yield return new StatisticsCsvRow { Section = "Filter", Key = "Keyword", Value = CsvExportFormatting.Cell(filter.Keyword) };
            yield return new StatisticsCsvRow { Section = "Filter", Key = "ComputerName", Value = CsvExportFormatting.Cell(filter.ComputerName) };
            yield return new StatisticsCsvRow { Section = "Filter", Key = "LogName", Value = CsvExportFormatting.Cell(filter.LogName) };
            yield return new StatisticsCsvRow
            {
                Section = "Filter",
                Key = "FromUtc",
                Value = filter.FromUtc.HasValue ? CsvExportFormatting.FormatUtc(filter.FromUtc.Value) : string.Empty
            };
            yield return new StatisticsCsvRow
            {
                Section = "Filter",
                Key = "ToUtc",
                Value = filter.ToUtc.HasValue ? CsvExportFormatting.FormatUtc(filter.ToUtc.Value) : string.Empty
            };
            yield return new StatisticsCsvRow { Section = "Filter", Key = "Limit", Value = filter.Limit.ToString() };
            yield return new StatisticsCsvRow
            {
                Section = "Filter",
                Key = "EventIds",
                Value = filter.EventIds is { Count: > 0 } ids ? string.Join(", ", ids) : string.Empty
            };
        }

        foreach (var pair in stats.FindingsBySeverity.OrderByDescending(p => p.Key))
        {
            yield return new StatisticsCsvRow { Section = "FindingsBySeverity", Key = pair.Key.ToString(), Value = pair.Value.ToString() };
        }

        foreach (var pair in stats.EventIdCounts.OrderByDescending(p => p.Value))
        {
            yield return new StatisticsCsvRow { Section = "EventIdCounts", Key = pair.Key.ToString(), Value = pair.Value.ToString() };
        }

        foreach (var pair in stats.UserCounts.OrderByDescending(p => p.Value))
        {
            yield return new StatisticsCsvRow { Section = "UserCounts", Key = CsvExportFormatting.Cell(pair.Key), Value = pair.Value.ToString() };
        }

        foreach (var pair in stats.ProcessCounts.OrderByDescending(p => p.Value))
        {
            yield return new StatisticsCsvRow { Section = "ProcessCounts", Key = CsvExportFormatting.Cell(pair.Key), Value = pair.Value.ToString() };
        }

        foreach (var pair in stats.SourceIpCounts.OrderByDescending(p => p.Value))
        {
            yield return new StatisticsCsvRow { Section = "SourceIpCounts", Key = CsvExportFormatting.Cell(pair.Key), Value = pair.Value.ToString() };
        }

        foreach (var pair in stats.EventsByHour.OrderBy(p => p.Key))
        {
            yield return new StatisticsCsvRow { Section = "EventsByHour", Key = $"{pair.Key:00}:00", Value = pair.Value.ToString() };
        }
    }
}
