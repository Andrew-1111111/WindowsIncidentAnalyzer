using WindowsIncidentAnalyzer.Models;

namespace WindowsIncidentAnalyzer.Exporters;

public sealed class InvestigationExport
{
    public string Title { get; set; } = "Windows Incident Investigation";

    public DateTime GeneratedUtc { get; set; } = DateTime.UtcNow;

    public EventQueryFilter? Filter { get; set; }

    public StatisticsResult Statistics { get; set; } = new();

    public IReadOnlyList<SecurityFinding> Findings { get; set; } = [];

    public IReadOnlyList<IocMatch> IocMatches { get; set; } = [];

    public IReadOnlyList<EventCorrelation> Correlations { get; set; } = [];

    public IReadOnlyList<TimelineItem> Timeline { get; set; } = [];

    /// <summary>
    /// Normalized Windows events referenced by findings, correlations, IOC matches, and timeline.
    /// </summary>
    public IReadOnlyList<WindowsEvent> Events { get; set; } = [];
}
