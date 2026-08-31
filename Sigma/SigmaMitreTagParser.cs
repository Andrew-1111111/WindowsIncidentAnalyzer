using System.Text.RegularExpressions;
using WindowsIncidentAnalyzer.Models;

namespace WindowsIncidentAnalyzer.Sigma;

public static class SigmaMitreTagParser
{
    private static readonly Regex TechniqueTag = new(
        @"^attack\.t\d+",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled);

    public static void Apply(IEnumerable<string> tags, FindingContext context)
    {
        var mitreTags = tags
            .Where(tag => tag.StartsWith("attack.", StringComparison.OrdinalIgnoreCase))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        context.MitreTags = mitreTags;
        context.MitreTechnique = mitreTags.FirstOrDefault(TechniqueTag.IsMatch);
        context.MitreTactic = mitreTags.FirstOrDefault(tag => !TechniqueTag.IsMatch(tag));
    }
}
