namespace WindowsIncidentAnalyzer.Persistence.Entities;

public sealed class EventEntity
{
    public long Id { get; set; }

    public string? ComputerName { get; set; }

    public string? LogName { get; set; }

    public string? ProviderName { get; set; }

    public int EventId { get; set; }

    public long? EventRecordId { get; set; }

    public string? EventKey { get; set; }

    public int CompletenessScore { get; set; }

    public DateTime TimeCreatedUtc { get; set; }

    public string? Level { get; set; }

    public string? User { get; set; }

    public string? Domain { get; set; }

    public string? ProcessName { get; set; }

    public int? ProcessId { get; set; }

    public string? ParentProcessName { get; set; }

    public int? ParentProcessId { get; set; }

    public string? CommandLine { get; set; }

    public string? SourceIpAddress { get; set; }

    public string? DestinationIpAddress { get; set; }

    public string? WorkstationName { get; set; }

    public string? TargetUserName { get; set; }

    public string? TargetDomainName { get; set; }

    public string? RawXml { get; set; }

    public string? PropertiesJson { get; set; }

    public string? ScriptBlock { get; set; }

    public string? ScriptBlockHash { get; set; }

    public string? Hashes { get; set; }

    public string? ProcessGuid { get; set; }

    public string? ParentProcessGuid { get; set; }

    public string? ParentCommandLine { get; set; }

    public int? SourcePort { get; set; }

    public int? DestinationPort { get; set; }

    public string? QueryName { get; set; }

    public string? TaskName { get; set; }

    public string? ServiceName { get; set; }

    public int? LogonType { get; set; }

    public string? ProcessPath { get; set; }
}
