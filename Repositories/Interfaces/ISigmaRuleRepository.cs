using WindowsIncidentAnalyzer.Sigma.Models;

namespace WindowsIncidentAnalyzer.Repositories;

public interface ISigmaRuleRepository
{
    IReadOnlyList<SigmaRule> GetRules();

    Task ReplaceAsync(IReadOnlyList<SigmaRule> rules, CancellationToken cancellationToken);

    int Count { get; }
}
