namespace WindowsIncidentAnalyzer.Models;

public sealed class IocMatch
{
    public string IocType { get; set; } = string.Empty;

    public string IocValue { get; set; } = string.Empty;

    public int EventId { get; set; }

    public DateTime TimestampUtc { get; set; }

    public string? Host { get; set; }

    public string? RelatedProcess { get; set; }

    public string? RelatedUser { get; set; }

    public string MatchedField { get; set; } = string.Empty;

    public long EventRowId { get; set; }
}
