using System.Globalization;
using System.Text.Json;
using CsvHelper.Configuration;

namespace WindowsIncidentAnalyzer.Exporters;

public sealed class FindingCsvRow
{
    public string Severity { get; init; } = string.Empty;
    public long FindingId { get; init; }
    public string RuleName { get; init; } = string.Empty;
    public string? RuleId { get; init; }
    public string? RuleTitle { get; init; }
    public string Title { get; init; } = string.Empty;
    public string? Category { get; init; }
    public string? EventType { get; init; }
    public string? CategoryMatchesEvent { get; init; }
    public string? SeverityMatchesEvent { get; init; }
    public string? RequestedSeverity { get; init; }
    public string TimeUtc { get; init; } = string.Empty;
    public string CreatedUtc { get; init; } = string.Empty;
    public string? Host { get; init; }
    public string? Domain { get; init; }
    public string? User { get; init; }
    public string? UserSid { get; init; }
    public string? LogonId { get; init; }
    public int? EventId { get; init; }
    public long? EventRecordId { get; init; }
    public string? Provider { get; init; }
    public string? Channel { get; init; }
    public int? ProcessId { get; init; }
    public int? ParentProcessId { get; init; }
    public string? ProcessName { get; init; }
    public string? Image { get; init; }
    public string? CommandLine { get; init; }
    public string? ParentImage { get; init; }
    public string? ParentCommandLine { get; init; }
    public string? WorkingDirectory { get; init; }
    public string? IntegrityLevel { get; init; }
    public string? ElevationType { get; init; }
    public string? SourceIp { get; init; }
    public int? SourcePort { get; init; }
    public string? DestinationIp { get; init; }
    public int? DestinationPort { get; init; }
    public string? FilePath { get; init; }
    public string? Sha256 { get; init; }
    public string? Md5 { get; init; }
    public string? Signer { get; init; }
    public string? OriginalFileName { get; init; }
    public string? SigmaId { get; init; }
    public string? SigmaStatus { get; init; }
    public string? MitreTactic { get; init; }
    public string? MitreTechnique { get; init; }
    public string? MitreTags { get; init; }
    public string? MatchedSelection { get; init; }
    public string? MatchedFields { get; init; }
    public string? MatchedValues { get; init; }
    public string? Condition { get; init; }
    public string? Reason { get; init; }
    public string Description { get; init; } = string.Empty;
    public string? Details { get; init; }
    public string RelatedEventRowIds { get; init; } = string.Empty;
    public string? RawEvent { get; init; }
    public string? RawXml { get; init; }
}

public sealed class TimelineCsvRow
{
    public string TimestampUtc { get; init; } = string.Empty;
    public long EventRowId { get; init; }
    public string? Host { get; init; }
    public int EventId { get; init; }
    public string? Source { get; init; }
    public string? User { get; init; }
    public string? Process { get; init; }
    public string? Ip { get; init; }
    public string Description { get; init; } = string.Empty;
    public string Severity { get; init; } = string.Empty;
}

public sealed class IocCsvRow
{
    public string IocType { get; init; } = string.Empty;
    public string IocValue { get; init; } = string.Empty;
    public int EventId { get; init; }
    public long EventRowId { get; init; }
    public string TimestampUtc { get; init; } = string.Empty;
    public string? Host { get; init; }
    public string? RelatedProcess { get; init; }
    public string? RelatedUser { get; init; }
    public string? MatchedField { get; init; }
}

public sealed class CorrelationCsvRow
{
    public long CorrelationId { get; init; }
    public string Severity { get; init; } = string.Empty;
    public string Scenario { get; init; } = string.Empty;
    public string Title { get; init; } = string.Empty;
    public string TimeUtc { get; init; } = string.Empty;
    public string CreatedUtc { get; init; } = string.Empty;
    public string? User { get; init; }
    public string? SourceIpAddress { get; init; }
    public string? ComputerName { get; init; }
    public string Interpretation { get; init; } = string.Empty;
    public string? Details { get; init; }
    public string RelatedEventRowIds { get; init; } = string.Empty;
}

public sealed class EventCsvRow
{
    public long EventRowId { get; init; }
    public string TimeCreatedUtc { get; init; } = string.Empty;
    public string? ComputerName { get; init; }
    public string? LogName { get; init; }
    public string? ProviderName { get; init; }
    public int EventId { get; init; }
    public long? EventRecordId { get; init; }
    public string? Level { get; init; }
    public string? User { get; init; }
    public string? Domain { get; init; }
    public string? TargetUserName { get; init; }
    public string? TargetDomainName { get; init; }
    public string? ProcessName { get; init; }
    public string? ProcessPath { get; init; }
    public int? ProcessId { get; init; }
    public string? ParentProcessName { get; init; }
    public int? ParentProcessId { get; init; }
    public string? ParentCommandLine { get; init; }
    public string? CommandLine { get; init; }
    public string? SourceIpAddress { get; init; }
    public string? DestinationIpAddress { get; init; }
    public int? SourcePort { get; init; }
    public int? DestinationPort { get; init; }
    public string? WorkstationName { get; init; }
    public int? LogonType { get; init; }
    public string? ScriptBlock { get; init; }
    public string? ScriptBlockHash { get; init; }
    public string? Hashes { get; init; }
    public string? ProcessGuid { get; init; }
    public string? ParentProcessGuid { get; init; }
    public string? QueryName { get; init; }
    public string? TaskName { get; init; }
    public string? ServiceName { get; init; }
    public string PropertiesJson { get; init; } = string.Empty;
    public string? RawXml { get; init; }
}

public sealed class StatisticsCsvRow
{
    public string Section { get; init; } = string.Empty;
    public string Key { get; init; } = string.Empty;
    public string Value { get; init; } = string.Empty;
}

public sealed class FindingCsvRowMap : ClassMap<FindingCsvRow>
{
    public FindingCsvRowMap()
    {
        Map(m => m.Severity).Name("Severity").Index(0);
        Map(m => m.FindingId).Name("Finding ID").Index(1);
        Map(m => m.RuleName).Name("Rule").Index(2);
        Map(m => m.RuleId).Name("Rule ID").Index(3);
        Map(m => m.RuleTitle).Name("Rule Title").Index(4);
        Map(m => m.Title).Name("Title").Index(5);
        Map(m => m.Category).Name("Category").Index(6);
        Map(m => m.EventType).Name("Event Type").Index(7);
        Map(m => m.CategoryMatchesEvent).Name("Category Matches Event").Index(8);
        Map(m => m.SeverityMatchesEvent).Name("Severity Matches Event").Index(9);
        Map(m => m.RequestedSeverity).Name("Requested Severity").Index(10);
        Map(m => m.TimeUtc).Name("Time UTC").Index(11);
        Map(m => m.CreatedUtc).Name("Created UTC").Index(12);
        Map(m => m.Host).Name("Host").Index(13);
        Map(m => m.Domain).Name("Domain").Index(14);
        Map(m => m.User).Name("User").Index(15);
        Map(m => m.UserSid).Name("User SID").Index(16);
        Map(m => m.LogonId).Name("Logon ID").Index(17);
        Map(m => m.EventId).Name("Event ID").Index(18);
        Map(m => m.EventRecordId).Name("Event Record ID").Index(19);
        Map(m => m.Provider).Name("Provider").Index(20);
        Map(m => m.Channel).Name("Channel").Index(21);
        Map(m => m.ProcessId).Name("PID").Index(22);
        Map(m => m.ParentProcessId).Name("PPID").Index(23);
        Map(m => m.ProcessName).Name("Process").Index(24);
        Map(m => m.Image).Name("Image").Index(25);
        Map(m => m.CommandLine).Name("Command Line").Index(26);
        Map(m => m.ParentImage).Name("Parent Image").Index(27);
        Map(m => m.ParentCommandLine).Name("Parent Command Line").Index(28);
        Map(m => m.WorkingDirectory).Name("Working Directory").Index(29);
        Map(m => m.IntegrityLevel).Name("Integrity Level").Index(30);
        Map(m => m.ElevationType).Name("Elevation").Index(31);
        Map(m => m.SourceIp).Name("Source IP").Index(32);
        Map(m => m.SourcePort).Name("Source Port").Index(33);
        Map(m => m.DestinationIp).Name("Destination IP").Index(34);
        Map(m => m.DestinationPort).Name("Destination Port").Index(35);
        Map(m => m.FilePath).Name("File Path").Index(36);
        Map(m => m.Sha256).Name("SHA256").Index(37);
        Map(m => m.Md5).Name("MD5").Index(38);
        Map(m => m.Signer).Name("Signer").Index(39);
        Map(m => m.OriginalFileName).Name("Original File Name").Index(40);
        Map(m => m.SigmaId).Name("Sigma ID").Index(41);
        Map(m => m.SigmaStatus).Name("Sigma Status").Index(42);
        Map(m => m.MitreTactic).Name("MITRE Tactic").Index(43);
        Map(m => m.MitreTechnique).Name("MITRE Technique").Index(44);
        Map(m => m.MitreTags).Name("MITRE Tags").Index(45);
        Map(m => m.MatchedSelection).Name("Sigma Selection").Index(46);
        Map(m => m.MatchedFields).Name("Matched Fields").Index(47);
        Map(m => m.MatchedValues).Name("Matched Values").Index(48);
        Map(m => m.Condition).Name("Condition").Index(49);
        Map(m => m.Reason).Name("Reason").Index(50);
        Map(m => m.Description).Name("Description").Index(51);
        Map(m => m.Details).Name("Details").Index(52);
        Map(m => m.RelatedEventRowIds).Name("Related Event IDs").Index(53);
        Map(m => m.RawEvent).Name("Raw Event JSON").Index(54);
        Map(m => m.RawXml).Name("Raw XML").Index(55);
    }
}

public sealed class TimelineCsvRowMap : ClassMap<TimelineCsvRow>
{
    public TimelineCsvRowMap()
    {
        Map(m => m.TimestampUtc).Name("Time UTC").Index(0);
        Map(m => m.EventRowId).Name("Event Row ID").Index(1);
        Map(m => m.Host).Name("Host").Index(2);
        Map(m => m.EventId).Name("Event ID").Index(3);
        Map(m => m.Source).Name("Source").Index(4);
        Map(m => m.User).Name("User").Index(5);
        Map(m => m.Process).Name("Process").Index(6);
        Map(m => m.Ip).Name("IP").Index(7);
        Map(m => m.Description).Name("Description").Index(8);
        Map(m => m.Severity).Name("Severity").Index(9);
    }
}

public sealed class IocCsvRowMap : ClassMap<IocCsvRow>
{
    public IocCsvRowMap()
    {
        Map(m => m.IocType).Name("IOC Type").Index(0);
        Map(m => m.IocValue).Name("IOC Value").Index(1);
        Map(m => m.EventId).Name("Event ID").Index(2);
        Map(m => m.EventRowId).Name("Event Row ID").Index(3);
        Map(m => m.TimestampUtc).Name("Time UTC").Index(4);
        Map(m => m.Host).Name("Host").Index(5);
        Map(m => m.RelatedProcess).Name("Process").Index(6);
        Map(m => m.RelatedUser).Name("User").Index(7);
        Map(m => m.MatchedField).Name("Matched Field").Index(8);
    }
}

public sealed class CorrelationCsvRowMap : ClassMap<CorrelationCsvRow>
{
    public CorrelationCsvRowMap()
    {
        Map(m => m.CorrelationId).Name("Correlation ID").Index(0);
        Map(m => m.Severity).Name("Severity").Index(1);
        Map(m => m.Scenario).Name("Scenario").Index(2);
        Map(m => m.Title).Name("Title").Index(3);
        Map(m => m.TimeUtc).Name("Time UTC").Index(4);
        Map(m => m.CreatedUtc).Name("Created UTC").Index(5);
        Map(m => m.User).Name("User").Index(6);
        Map(m => m.SourceIpAddress).Name("Source IP").Index(7);
        Map(m => m.ComputerName).Name("Host").Index(8);
        Map(m => m.Interpretation).Name("Interpretation").Index(9);
        Map(m => m.Details).Name("Details").Index(10);
        Map(m => m.RelatedEventRowIds).Name("Related Event IDs").Index(11);
    }
}

public sealed class EventCsvRowMap : ClassMap<EventCsvRow>
{
    public EventCsvRowMap()
    {
        Map(m => m.EventRowId).Name("Event Row ID").Index(0);
        Map(m => m.TimeCreatedUtc).Name("Time UTC").Index(1);
        Map(m => m.ComputerName).Name("Host").Index(2);
        Map(m => m.LogName).Name("Log").Index(3);
        Map(m => m.ProviderName).Name("Provider").Index(4);
        Map(m => m.EventId).Name("Event ID").Index(5);
        Map(m => m.EventRecordId).Name("Event Record ID").Index(6);
        Map(m => m.Level).Name("Level").Index(7);
        Map(m => m.User).Name("User").Index(8);
        Map(m => m.Domain).Name("Domain").Index(9);
        Map(m => m.TargetUserName).Name("Target User").Index(10);
        Map(m => m.TargetDomainName).Name("Target Domain").Index(11);
        Map(m => m.ProcessName).Name("Process").Index(12);
        Map(m => m.ProcessPath).Name("Image").Index(13);
        Map(m => m.ProcessId).Name("PID").Index(14);
        Map(m => m.ParentProcessName).Name("Parent Process").Index(15);
        Map(m => m.ParentProcessId).Name("PPID").Index(16);
        Map(m => m.ParentCommandLine).Name("Parent Command Line").Index(17);
        Map(m => m.CommandLine).Name("Command Line").Index(18);
        Map(m => m.SourceIpAddress).Name("Source IP").Index(19);
        Map(m => m.DestinationIpAddress).Name("Destination IP").Index(20);
        Map(m => m.SourcePort).Name("Source Port").Index(21);
        Map(m => m.DestinationPort).Name("Destination Port").Index(22);
        Map(m => m.WorkstationName).Name("Workstation").Index(23);
        Map(m => m.LogonType).Name("Logon Type").Index(24);
        Map(m => m.ScriptBlock).Name("Script Block").Index(25);
        Map(m => m.ScriptBlockHash).Name("Script Block Hash").Index(26);
        Map(m => m.Hashes).Name("Hashes").Index(27);
        Map(m => m.ProcessGuid).Name("Process GUID").Index(28);
        Map(m => m.ParentProcessGuid).Name("Parent Process GUID").Index(29);
        Map(m => m.QueryName).Name("DNS Query").Index(30);
        Map(m => m.TaskName).Name("Task Name").Index(31);
        Map(m => m.ServiceName).Name("Service Name").Index(32);
        Map(m => m.PropertiesJson).Name("Properties JSON").Index(33);
        Map(m => m.RawXml).Name("Raw XML").Index(34);
    }
}

public sealed class StatisticsCsvRowMap : ClassMap<StatisticsCsvRow>
{
    public StatisticsCsvRowMap()
    {
        Map(m => m.Section).Name("Section").Index(0);
        Map(m => m.Key).Name("Key").Index(1);
        Map(m => m.Value).Name("Value").Index(2);
    }
}

internal static class CsvExportFormatting
{
    private const int MaxCellLength = 32_000;

    public static string FormatUtc(DateTime value) =>
        value.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture);

    public static string FormatIds(IReadOnlyList<long> ids) =>
        ids.Count == 0 ? string.Empty : string.Join(", ", ids);

    public static string FormatList(IReadOnlyList<string> values) =>
        values.Count == 0 ? string.Empty : string.Join(" | ", values.Select(Cell));

    public static string FormatNullableBool(bool? value) =>
        value switch
        {
            true => "yes",
            false => "no",
            _ => string.Empty
        };

    public static string FormatProperties(IReadOnlyDictionary<string, string> properties)
    {
        if (properties.Count == 0)
        {
            return string.Empty;
        }

        return Cell(JsonSerializer.Serialize(properties));
    }

    public static string Cell(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return string.Empty;
        }

        var normalized = value
            .Replace("\r\n", " ", StringComparison.Ordinal)
            .Replace('\r', ' ')
            .Replace('\n', ' ')
            .Replace('\t', ' ')
            .Trim();

        return normalized.Length <= MaxCellLength
            ? normalized
            : normalized[..MaxCellLength];
    }
}
