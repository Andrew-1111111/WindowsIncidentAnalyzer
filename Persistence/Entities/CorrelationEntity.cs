namespace WindowsIncidentAnalyzer.Persistence.Entities;

public sealed class CorrelationEntity
{
    public long Id { get; set; }

    public string Scenario { get; set; } = string.Empty;

    public string Title { get; set; } = string.Empty;

    public string? Interpretation { get; set; }

    public string Severity { get; set; } = string.Empty;

    public DateTime TimeUtc { get; set; }

    public string? User { get; set; }

    public string? ComputerName { get; set; }

    public string? SourceIpAddress { get; set; }

    public string? Details { get; set; }

    public string? RelatedEventRowIds { get; set; }

    public DateTime CreatedUtc { get; set; }
}
