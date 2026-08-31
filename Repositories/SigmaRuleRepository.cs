using WindowsIncidentAnalyzer.Sigma.Models;

namespace WindowsIncidentAnalyzer.Repositories;

public sealed class SigmaRuleRepository : ISigmaRuleRepository
{
    private readonly object _lock = new();
    private List<SigmaRule> _rules = [];

    public int Count
    {
        get
        {
            lock (_lock)
            {
                return _rules.Count;
            }
        }
    }

    public IReadOnlyList<SigmaRule> GetRules()
    {
        lock (_lock)
        {
            return _rules.ToList();
        }
    }

    public Task ReplaceAsync(IReadOnlyList<SigmaRule> rules, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (_lock)
        {
            _rules = rules.ToList();
        }

        return Task.CompletedTask;
    }
}
