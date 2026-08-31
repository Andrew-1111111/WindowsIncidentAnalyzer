namespace WindowsIncidentAnalyzer.Models;

public sealed class SecurityFinding
{
    public long Id { get; set; }

    public string RuleName { get; set; } = string.Empty;

    public string Title { get; set; } = string.Empty;

    public string Description { get; set; } = string.Empty;

    public DetectionSeverity Severity { get; set; }

    public DateTime TimeUtc { get; set; }

    public string? ComputerName { get; set; }

    public string? User { get; set; }

    public string? SourceIpAddress { get; set; }

    public string? ProcessName { get; set; }

    public string? Details { get; set; }

    public FindingContext Context { get; set; } = new();

    public List<long> RelatedEventRowIds { get; set; } = [];

    public DateTime CreatedUtc { get; set; } = DateTime.UtcNow;
}
