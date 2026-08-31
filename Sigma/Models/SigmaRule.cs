using WindowsIncidentAnalyzer.Models;

namespace WindowsIncidentAnalyzer.Sigma.Models;

public sealed class SigmaRule
{
    public string Title { get; set; } = string.Empty;

    public string? Id { get; set; }

    public string? Description { get; set; }

    public string? Status { get; set; }

    public string? Author { get; set; }

    public SigmaLogsource Logsource { get; set; } = new();

    public Dictionary<string, SigmaSelection> Selections { get; set; } = new(StringComparer.OrdinalIgnoreCase);

    public string Condition { get; set; } = string.Empty;

    public DetectionSeverity Severity { get; set; } = DetectionSeverity.Medium;

    public List<string> Tags { get; set; } = [];

    public string SourcePath { get; set; } = string.Empty;

    public IReadOnlyList<int> RelevantEventIds { get; set; } = [];
}

public sealed class SigmaLogsource
{
    public string? Product { get; set; }

    public string? Service { get; set; }

    public string? Category { get; set; }

    public string? Definition { get; set; }
}

public sealed class SigmaSelection
{
    public List<SigmaFieldMatch> FieldMatches { get; set; } = [];

    public List<string> Keywords { get; set; } = [];
}

public sealed class SigmaFieldMatch
{
    public string Field { get; set; } = string.Empty;

    public SigmaFieldModifier Modifier { get; set; } = SigmaFieldModifier.Equals;

    public List<string> Values { get; set; } = [];
}

public enum SigmaFieldModifier
{
    Equals,
    Contains,
    StartsWith,
    EndsWith,
    Regex
}
