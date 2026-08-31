namespace WindowsIncidentAnalyzer.Models;

public sealed class TimelineItem
{
    public DateTime TimestampUtc { get; set; }

    public string? Host { get; set; }

    public int EventId { get; set; }

    public string? Source { get; set; }

    public string? User { get; set; }

    public string? Process { get; set; }

    public string? Ip { get; set; }

    public string Description { get; set; } = string.Empty;

    public DetectionSeverity Severity { get; set; }

    public long EventRowId { get; set; }
}
