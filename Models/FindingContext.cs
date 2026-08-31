namespace WindowsIncidentAnalyzer.Models;

/// <summary>
/// Structured investigation context for a security finding.
/// Populated from the source Windows event and rule-specific metadata (e.g. Sigma).
/// </summary>
public sealed class FindingContext
{
    // Identification
    public string? RuleId { get; set; }

    public string? RuleTitle { get; set; }

    public string? Category { get; set; }

    /// <summary>
    /// Sigma-style category inferred from EventId, provider, and channel.
    /// </summary>
    public string? EventType { get; set; }

    /// <summary>
    /// True when <see cref="Category"/> matches the actual event; false on mismatch; null when not applicable.
    /// </summary>
    public bool? CategoryMatchesEvent { get; set; }

    /// <summary>
    /// True when CRIT/HIGH severity is justified for the source event; false when severity was capped.
    /// </summary>
    public bool? SeverityMatchesEvent { get; set; }

    /// <summary>
    /// Original requested severity before event-based validation (only set when adjusted).
    /// </summary>
    public DetectionSeverity? RequestedSeverity { get; set; }

    public DetectionSeverity? Severity { get; set; }

    // Time
    public DateTime? TimestampUtc { get; set; }

    // Windows Event
    public int? EventId { get; set; }

    public long? EventRecordId { get; set; }

    public string? Provider { get; set; }

    public string? Channel { get; set; }

    // Host / User / Session
    public string? Host { get; set; }

    public string? Domain { get; set; }

    public string? User { get; set; }

    public string? UserSid { get; set; }

    public string? LogonId { get; set; }

    // Process
    public int? ProcessId { get; set; }

    public int? ParentProcessId { get; set; }

    public string? ProcessName { get; set; }

    public string? Image { get; set; }

    public string? CommandLine { get; set; }

    public string? ParentImage { get; set; }

    public string? ParentCommandLine { get; set; }

    public string? WorkingDirectory { get; set; }

    public string? IntegrityLevel { get; set; }

    public string? ElevationType { get; set; }

    // File
    public string? FilePath { get; set; }

    public string? Sha256 { get; set; }

    public string? Md5 { get; set; }

    public string? Signer { get; set; }

    public string? OriginalFileName { get; set; }

    // Network
    public string? SourceIp { get; set; }

    public int? SourcePort { get; set; }

    public string? DestinationIp { get; set; }

    public int? DestinationPort { get; set; }

    // Sigma
    public string? SigmaId { get; set; }

    public string? SigmaStatus { get; set; }

    public List<string> MitreTags { get; set; } = [];

    public string? MitreTactic { get; set; }

    public string? MitreTechnique { get; set; }

    public List<string> MatchedFields { get; set; } = [];

    public List<string> MatchedValues { get; set; } = [];

    public string? MatchedSelection { get; set; }

    public string? Condition { get; set; }

    public string? Reason { get; set; }

    // Evidence
    public string? RawEvent { get; set; }

    public string? RawXml { get; set; }
}
