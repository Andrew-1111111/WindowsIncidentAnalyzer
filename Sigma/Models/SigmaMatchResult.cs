using WindowsIncidentAnalyzer.Sigma.Models;

namespace WindowsIncidentAnalyzer.Sigma.Models;

public sealed class SigmaFieldMatchDetail
{
    public string SelectionName { get; set; } = string.Empty;

    public string Field { get; set; } = string.Empty;

    public string ActualValue { get; set; } = string.Empty;

    public string ExpectedValue { get; set; } = string.Empty;

    public SigmaFieldModifier Modifier { get; set; } = SigmaFieldModifier.Equals;
}

public sealed class SigmaMatchResult
{
    public IReadOnlyList<string> MatchedSelections { get; init; } = [];

    public IReadOnlyList<SigmaFieldMatchDetail> FieldMatches { get; init; } = [];

    public string? Reason { get; init; }

    public IReadOnlyList<string> MatchedFields =>
        FieldMatches.Select(match => match.Field).Distinct(StringComparer.OrdinalIgnoreCase).ToList();

    public IReadOnlyList<string> MatchedValues =>
        FieldMatches.Select(match => match.ActualValue).ToList();
}
