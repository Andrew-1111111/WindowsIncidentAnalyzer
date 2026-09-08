namespace WindowsIncidentAnalyzer.Persistence.Entities;

public sealed class FindingEntity
{
    public long Id { get; set; }

    public string RuleName { get; set; } = string.Empty;

    public string Title { get; set; } = string.Empty;

    public string? Description { get; set; }

    public string Severity { get; set; } = string.Empty;

    public DateTime TimeUtc { get; set; }

    public string? ComputerName { get; set; }

    public string? User { get; set; }

    public string? SourceIpAddress { get; set; }

    public string? ProcessName { get; set; }

    public string? Details { get; set; }

    public string? RelatedEventRowIds { get; set; }

    public string? ContextJson { get; set; }

    public DateTime CreatedUtc { get; set; }
}
