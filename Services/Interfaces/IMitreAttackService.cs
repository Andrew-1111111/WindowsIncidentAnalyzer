namespace WindowsIncidentAnalyzer.Services;

public interface IMitreAttackService
{
    Task EnsureLoadedAsync(CancellationToken cancellationToken);

    Task<int> LoadFromFileAsync(string path, CancellationToken cancellationToken);

    Task<int> UpdateFromMitreCtiAsync(CancellationToken cancellationToken);

    IReadOnlyList<Models.MitreAttackTechnique> GetTechniques();

    IReadOnlyList<Models.MitreAttackTactic> GetTactics();

    bool TryGetTechnique(string techniqueId, out Models.MitreAttackTechnique technique);

    bool TryGetTactic(string shortName, out Models.MitreAttackTactic tactic);
}
