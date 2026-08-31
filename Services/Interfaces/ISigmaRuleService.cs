using WindowsIncidentAnalyzer.Sigma.Models;

namespace WindowsIncidentAnalyzer.Services;

public interface ISigmaRuleService
{
    Task<int> LoadFromDirectoryAsync(string directory, CancellationToken cancellationToken);

    Task<int> UpdateFromSigmaHqAsync(CancellationToken cancellationToken);

    Task EnsureLoadedAsync(CancellationToken cancellationToken);

    IReadOnlyList<SigmaRule> GetRules();
}
