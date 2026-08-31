namespace WindowsIncidentAnalyzer.Models;

public sealed class InvestigationSummary
{
    public int EventsAnalyzed { get; set; }

    public IReadOnlyList<SecurityFinding> Findings { get; set; } = [];

    public IReadOnlyList<EventCorrelation> Correlations { get; set; } = [];

    public IReadOnlyList<IocMatch> IocMatches { get; set; } = [];

    public IReadOnlyList<string> TopSuspiciousUsers { get; set; } = [];

    public IReadOnlyList<string> TopSuspiciousIps { get; set; } = [];

    public int CriticalCount => Findings.Count(f => f.Severity == DetectionSeverity.Critical);

    public int HighCount => Findings.Count(f => f.Severity == DetectionSeverity.High);

    public int MediumCount => Findings.Count(f => f.Severity == DetectionSeverity.Medium);

    public int LowCount => Findings.Count(f => f.Severity == DetectionSeverity.Low);

    public int InfoCount => Findings.Count(f => f.Severity == DetectionSeverity.Info);
}
