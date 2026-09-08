using WindowsIncidentAnalyzer.Models;

namespace WindowsIncidentAnalyzer.Repositories;

public interface IMitreAttackRepository
{
    int TacticCount { get; }

    int TechniqueCount { get; }

    Task ReplaceAsync(
        IReadOnlyList<MitreAttackTactic> tactics,
        IReadOnlyList<MitreAttackTechnique> techniques,
        CancellationToken cancellationToken);

    bool TryGetTechnique(string techniqueId, out MitreAttackTechnique technique);

    bool TryGetTactic(string shortName, out MitreAttackTactic tactic);

    string? GetTacticName(string shortName);

    IReadOnlyList<MitreAttackTechnique> GetTechniques();

    IReadOnlyList<MitreAttackTactic> GetTactics();
}
