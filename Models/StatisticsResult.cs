namespace WindowsIncidentAnalyzer.Models;

public sealed class StatisticsResult
{
    public int TotalEvents { get; set; }

    public int TotalFindings { get; set; }

    public Dictionary<int, int> EventIdCounts { get; set; } = [];

    public Dictionary<string, int> UserCounts { get; set; } = [];

    public Dictionary<string, int> ProcessCounts { get; set; } = [];

    public Dictionary<string, int> SourceIpCounts { get; set; } = [];

    public Dictionary<int, int> EventsByHour { get; set; } = [];

    public Dictionary<DetectionSeverity, int> FindingsBySeverity { get; set; } = [];
}
