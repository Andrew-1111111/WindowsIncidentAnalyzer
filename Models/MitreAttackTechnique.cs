namespace WindowsIncidentAnalyzer.Models;

public sealed class MitreAttackTechnique
{
    public string ExternalId { get; init; } = string.Empty;

    public string Name { get; init; } = string.Empty;

    public string? Description { get; init; }

    public string? Url { get; init; }

    public List<string> TacticShortNames { get; init; } = [];
}
