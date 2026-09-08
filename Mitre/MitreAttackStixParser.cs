using System.Text.Json;
using WindowsIncidentAnalyzer.Models;

namespace WindowsIncidentAnalyzer.Mitre;

public static class MitreAttackStixParser
{
    public static MitreAttackCatalog Parse(string json)
    {
        using var document = JsonDocument.Parse(json);
        if (!document.RootElement.TryGetProperty("objects", out var objects))
        {
            return MitreAttackCatalog.Empty;
        }

        var tactics = new List<MitreAttackTactic>();
        var techniques = new List<MitreAttackTechnique>();

        foreach (var element in objects.EnumerateArray())
        {
            if (!element.TryGetProperty("type", out var typeProperty))
            {
                continue;
            }

            var type = typeProperty.GetString();
            if (string.Equals(type, "x-mitre-tactic", StringComparison.OrdinalIgnoreCase))
            {
                var tactic = ParseTactic(element);
                if (tactic != null)
                {
                    tactics.Add(tactic);
                }

                continue;
            }

            if (!string.Equals(type, "attack-pattern", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            if (IsDeprecatedOrRevoked(element))
            {
                continue;
            }

            var technique = ParseTechnique(element);
            if (technique != null)
            {
                techniques.Add(technique);
            }
        }

        return new MitreAttackCatalog(tactics, techniques);
    }

    private static MitreAttackTactic? ParseTactic(JsonElement element)
    {
        var shortName = ReadString(element, "x_mitre_shortname");
        var name = ReadString(element, "name");
        if (string.IsNullOrWhiteSpace(shortName) || string.IsNullOrWhiteSpace(name))
        {
            return null;
        }

        var reference = ReadMitreReference(element);
        return new MitreAttackTactic
        {
            ShortName = shortName.Trim().ToLowerInvariant(),
            Name = name.Trim(),
            ExternalId = reference.ExternalId,
            Url = reference.Url
        };
    }

    private static MitreAttackTechnique? ParseTechnique(JsonElement element)
    {
        var reference = ReadMitreReference(element);
        if (string.IsNullOrWhiteSpace(reference.ExternalId))
        {
            return null;
        }

        var name = ReadString(element, "name");
        if (string.IsNullOrWhiteSpace(name))
        {
            return null;
        }

        var tacticShortNames = new List<string>();
        if (element.TryGetProperty("kill_chain_phases", out var phases))
        {
            foreach (var phase in phases.EnumerateArray())
            {
                var phaseName = ReadString(phase, "phase_name");
                if (!string.IsNullOrWhiteSpace(phaseName))
                {
                    tacticShortNames.Add(phaseName.Trim().ToLowerInvariant());
                }
            }
        }

        return new MitreAttackTechnique
        {
            ExternalId = reference.ExternalId!,
            Name = name.Trim(),
            Description = ReadString(element, "description"),
            Url = reference.Url,
            TacticShortNames = tacticShortNames.Distinct(StringComparer.OrdinalIgnoreCase).ToList()
        };
    }

    private static bool IsDeprecatedOrRevoked(JsonElement element) =>
        (element.TryGetProperty("x_mitre_deprecated", out var deprecated) && deprecated.ValueKind == JsonValueKind.True) ||
        (element.TryGetProperty("revoked", out var revoked) && revoked.ValueKind == JsonValueKind.True);

    private static (string? ExternalId, string? Url) ReadMitreReference(JsonElement element)
    {
        if (!element.TryGetProperty("external_references", out var references))
        {
            return (null, null);
        }

        foreach (var reference in references.EnumerateArray())
        {
            var source = ReadString(reference, "source_name");
            if (!string.Equals(source, "mitre-attack", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            return (ReadString(reference, "external_id"), ReadString(reference, "url"));
        }

        return (null, null);
    }

    private static string? ReadString(JsonElement element, string propertyName) =>
        element.TryGetProperty(propertyName, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;
}

public sealed class MitreAttackCatalog
{
    public static MitreAttackCatalog Empty { get; } = new([], []);

    public MitreAttackCatalog(
        IReadOnlyList<MitreAttackTactic> tactics,
        IReadOnlyList<MitreAttackTechnique> techniques)
    {
        Tactics = tactics;
        Techniques = techniques;
    }

    public IReadOnlyList<MitreAttackTactic> Tactics { get; }

    public IReadOnlyList<MitreAttackTechnique> Techniques { get; }
}
