namespace WindowsIncidentAnalyzer.Models;

public sealed record EventQueryFilter
{
    public IReadOnlyList<int>? EventIds { get; init; }

    public string? User { get; init; }

    public string? IpAddress { get; init; }

    public string? ProcessName { get; init; }

    public string? Keyword { get; init; }

    public DateTime? FromUtc { get; init; }

    public DateTime? ToUtc { get; init; }

    public IReadOnlyList<TimeRange>? TimeRanges { get; init; }

    public string? ComputerName { get; init; }

    public string? LogName { get; init; }

    public int Limit { get; init; } = 1000;

    public int Offset { get; init; }
}
