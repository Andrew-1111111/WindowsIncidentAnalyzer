using WindowsIncidentAnalyzer.Models;

namespace WindowsIncidentAnalyzer.Repositories;

public sealed class MitreAttackRepository : IMitreAttackRepository
{
    private readonly object _lock = new();
    private Dictionary<string, MitreAttackTactic> _tacticsByShortName = new(StringComparer.OrdinalIgnoreCase);
    private Dictionary<string, MitreAttackTechnique> _techniquesById = new(StringComparer.OrdinalIgnoreCase);

    public int TacticCount
    {
        get
        {
            lock (_lock)
            {
                return _tacticsByShortName.Count;
            }
        }
    }

    public int TechniqueCount
    {
        get
        {
            lock (_lock)
            {
                return _techniquesById.Count;
            }
        }
    }

    public Task ReplaceAsync(
        IReadOnlyList<MitreAttackTactic> tactics,
        IReadOnlyList<MitreAttackTechnique> techniques,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var tacticMap = tactics
            .Where(t => !string.IsNullOrWhiteSpace(t.ShortName))
            .GroupBy(t => t.ShortName, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.First(), StringComparer.OrdinalIgnoreCase);

        var techniqueMap = techniques
            .Where(t => !string.IsNullOrWhiteSpace(t.ExternalId))
            .GroupBy(t => NormalizeTechniqueId(t.ExternalId), StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.First(), StringComparer.OrdinalIgnoreCase);

        lock (_lock)
        {
            _tacticsByShortName = tacticMap;
            _techniquesById = techniqueMap;
        }

        return Task.CompletedTask;
    }

    public bool TryGetTechnique(string techniqueId, out MitreAttackTechnique technique)
    {
        lock (_lock)
        {
            return _techniquesById.TryGetValue(NormalizeTechniqueId(techniqueId), out technique!);
        }
    }

    public bool TryGetTactic(string shortName, out MitreAttackTactic tactic)
    {
        var normalized = NormalizeTacticShortName(shortName);
        lock (_lock)
        {
            return _tacticsByShortName.TryGetValue(normalized, out tactic!);
        }
    }

    public string? GetTacticName(string shortName)
    {
        return TryGetTactic(shortName, out var tactic) ? tactic.Name : null;
    }

    public IReadOnlyList<MitreAttackTechnique> GetTechniques()
    {
        lock (_lock)
        {
            return _techniquesById.Values.OrderBy(t => t.ExternalId, StringComparer.OrdinalIgnoreCase).ToList();
        }
    }

    public IReadOnlyList<MitreAttackTactic> GetTactics()
    {
        lock (_lock)
        {
            return _tacticsByShortName.Values.OrderBy(t => t.Name, StringComparer.OrdinalIgnoreCase).ToList();
        }
    }

    public static string NormalizeTechniqueId(string value)
    {
        var trimmed = value.Trim();
        if (trimmed.StartsWith("attack.", StringComparison.OrdinalIgnoreCase))
        {
            trimmed = trimmed["attack.".Length..];
        }

        return trimmed.ToUpperInvariant();
    }

    public static string NormalizeTacticShortName(string value)
    {
        var trimmed = value.Trim();
        if (trimmed.StartsWith("attack.", StringComparison.OrdinalIgnoreCase))
        {
            trimmed = trimmed["attack.".Length..];
        }

        return trimmed.ToLowerInvariant();
    }
}
