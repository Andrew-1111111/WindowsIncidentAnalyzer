namespace WindowsIncidentAnalyzer.Models;

public sealed class Ioc
{
    public long Id { get; set; }

    public string Type { get; set; } = string.Empty;

    public string Value { get; set; } = string.Empty;

    public string? Source { get; set; }

    public string? Comment { get; set; }

    public DateTime ImportedUtc { get; set; } = DateTime.UtcNow;
}
