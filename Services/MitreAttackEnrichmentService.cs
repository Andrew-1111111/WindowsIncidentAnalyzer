using WindowsIncidentAnalyzer.Models;
using WindowsIncidentAnalyzer.Repositories;

namespace WindowsIncidentAnalyzer.Services;

public sealed class MitreAttackEnrichmentService(IMitreAttackRepository repository) : IMitreAttackEnrichmentService
{
    public void Enrich(FindingContext context)
    {
        if (!string.IsNullOrWhiteSpace(context.MitreTechnique))
        {
            var techniqueId = MitreAttackRepository.NormalizeTechniqueId(context.MitreTechnique);
            if (repository.TryGetTechnique(techniqueId, out var technique))
            {
                context.MitreTechniqueName = technique.Name;
                context.MitreUrl ??= technique.Url;
                if (string.IsNullOrWhiteSpace(context.MitreTacticName) && technique.TacticShortNames.Count > 0)
                {
                    context.MitreTacticName = string.Join(
                        ", ",
                        technique.TacticShortNames
                            .Select(repository.GetTacticName)
                            .Where(name => !string.IsNullOrWhiteSpace(name)));
                }
            }
            else if (techniqueId.Contains('.', StringComparison.Ordinal))
            {
                var parentId = techniqueId[..techniqueId.IndexOf('.', StringComparison.Ordinal)];
                if (repository.TryGetTechnique(parentId, out var parentTechnique))
                {
                    context.MitreTechniqueName = parentTechnique.Name;
                    context.MitreUrl ??= parentTechnique.Url;
                }
            }
        }

        if (!string.IsNullOrWhiteSpace(context.MitreTactic))
        {
            context.MitreTacticName ??= repository.GetTacticName(context.MitreTactic);
        }
    }

    public void Enrich(IEnumerable<SecurityFinding> findings)
    {
        foreach (var finding in findings)
        {
            Enrich(finding.Context);
        }
    }
}
