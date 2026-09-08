using WindowsIncidentAnalyzer.Models;

namespace WindowsIncidentAnalyzer.Services;

public sealed class EventLogQueryOptions
{
    public string? LogName { get; init; }

    public string? EvtxPath { get; init; }

    public DateTime? FromUtc { get; init; }

    public DateTime? ToUtc { get; init; }

    public IReadOnlyList<TimeRange>? TimeRanges { get; init; }

    public IReadOnlyList<int>? EventIds { get; init; }

    public int? Limit { get; init; }

    /// <summary>
    /// When true, access denied on a channel fails the command.
    /// When false (default multi-log collect), the channel is skipped.
    /// </summary>
    public bool ThrowOnAccessDenied { get; init; }

    public IList<string>? AccessDeniedLogs { get; init; }

    public IList<string>? MissingLogs { get; init; }
}
