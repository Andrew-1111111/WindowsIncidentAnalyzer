namespace WindowsIncidentAnalyzer.Models;

public sealed class MitreAttackTactic
{
    public string ShortName { get; init; } = string.Empty;

    public string Name { get; init; } = string.Empty;

    public string? ExternalId { get; init; }

    public string? Url { get; init; }
}
