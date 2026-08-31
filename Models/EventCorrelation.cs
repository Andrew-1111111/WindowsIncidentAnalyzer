namespace WindowsIncidentAnalyzer.Models;

public sealed class EventCorrelation
{
    public long Id { get; set; }

    public string Scenario { get; set; } = string.Empty;

    public string Title { get; set; } = string.Empty;

    public string Interpretation { get; set; } = string.Empty;

    public DetectionSeverity Severity { get; set; }

    public DateTime TimeUtc { get; set; }

    public string? User { get; set; }

    public string? ComputerName { get; set; }

    public string? SourceIpAddress { get; set; }

    public string Details { get; set; } = string.Empty;

    public List<long> RelatedEventRowIds { get; set; } = [];

    public DateTime CreatedUtc { get; set; } = DateTime.UtcNow;
}
