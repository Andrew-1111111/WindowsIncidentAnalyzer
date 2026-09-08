using WindowsIncidentAnalyzer.Configuration;
using WindowsIncidentAnalyzer.Sigma.Models;

namespace WindowsIncidentAnalyzer.Sigma;

internal static class SigmaRuleFilter
{
    public static List<SigmaRule> Apply(IReadOnlyList<SigmaRule> rules, SigmaRulesOptions options) =>
        rules
            .Where(rule => options.IncludeExperimental || !IsStatus(rule, "experimental"))
            .Where(rule => options.IncludeDeprecated || !IsStatus(rule, "deprecated"))
            .Where(rule => options.IncludeUnsupported || !IsStatus(rule, "unsupported"))
            .Where(rule => options.IncludeEmergingThreats || !HasTag(rule, "detection.emerging_threats"))
            .Where(rule => options.IncludeThreatHunting || !HasTag(rule, "detection.threat_hunting"))
            .Where(rule => string.IsNullOrWhiteSpace(rule.Logsource.Product) ||
                           rule.Logsource.Product.Equals("windows", StringComparison.OrdinalIgnoreCase))
            .ToList();

    private static bool IsStatus(SigmaRule rule, string status) =>
        string.Equals(rule.Status, status, StringComparison.OrdinalIgnoreCase);

    private static bool HasTag(SigmaRule rule, string tag) =>
        rule.Tags.Any(candidate => candidate.Equals(tag, StringComparison.OrdinalIgnoreCase));
}
