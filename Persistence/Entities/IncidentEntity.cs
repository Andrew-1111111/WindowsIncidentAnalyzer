namespace WindowsIncidentAnalyzer.Persistence.Entities;

public sealed class IncidentEntity
{
    public long Id { get; set; }

    public string Title { get; set; } = string.Empty;

    public DateTime CreatedUtc { get; set; }

    public int EventsAnalyzed { get; set; }

    public int FindingsCritical { get; set; }

    public int FindingsHigh { get; set; }

    public int FindingsMedium { get; set; }

    public int FindingsLow { get; set; }

    public int FindingsInfo { get; set; }

    public string? SummaryJson { get; set; }
}
