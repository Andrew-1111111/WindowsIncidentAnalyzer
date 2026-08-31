namespace WindowsIncidentAnalyzer.Models;

public sealed class Incident
{
    public long Id { get; set; }

    public string Title { get; set; } = "Windows investigation";

    public DateTime CreatedUtc { get; set; } = DateTime.UtcNow;

    public int EventsAnalyzed { get; set; }

    public int FindingsCritical { get; set; }

    public int FindingsHigh { get; set; }

    public int FindingsMedium { get; set; }

    public int FindingsLow { get; set; }

    public int FindingsInfo { get; set; }

    public string? SummaryJson { get; set; }
}
