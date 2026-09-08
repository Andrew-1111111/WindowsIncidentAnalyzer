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
    public string? MitreTechniqueName { get; init; }
    public string? MitreTacticName { get; init; }
    public string? MitreUrl { get; init; }
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

public sealed class CveCsvRow
{
    public string CveId { get; init; } = string.Empty;
    public string? VulnerabilityName { get; init; }
    public string? ShortDescription { get; init; }
    public string? VendorProject { get; init; }
    public string? Product { get; init; }
    public string? KnownRansomwareUse { get; init; }
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
