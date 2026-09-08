using WindowsIncidentAnalyzer.Configuration;
using WindowsIncidentAnalyzer.Sigma;
using WindowsIncidentAnalyzer.Sigma.Models;
using Xunit;

namespace WindowsIncidentAnalyzer.Tests.UnitTests;

public sealed class SigmaRuleFilterTests
{
    [Fact]
    public void FilterRules_ExcludesEmergingThreatsAndThreatHuntingByDefault()
    {
        var rules = new[]
        {
            CreateRule("baseline", tags: []),
            CreateRule("emerging", tags: ["detection.emerging_threats"]),
            CreateRule("hunting", tags: ["detection.threat_hunting"])
        };

        var filtered = SigmaRuleFilter.Apply(rules, new SigmaRulesOptions());

        Assert.Single(filtered);
        Assert.Equal("baseline", filtered[0].Title);
    }

    [Fact]
    public void FilterRules_IncludesTaggedRulesWhenEnabled()
    {
        var rules = new[]
        {
            CreateRule("emerging", tags: ["detection.emerging_threats"]),
            CreateRule("hunting", tags: ["detection.threat_hunting"])
        };

        var filtered = SigmaRuleFilter.Apply(
            rules,
            new SigmaRulesOptions
            {
                IncludeEmergingThreats = true,
                IncludeThreatHunting = true
            });

        Assert.Equal(2, filtered.Count);
    }

    private static SigmaRule CreateRule(string title, IReadOnlyList<string> tags) =>
        new()
        {
            Title = title,
            Condition = "selection",
            Tags = tags.ToList(),
            Selections = new Dictionary<string, SigmaSelection>(StringComparer.OrdinalIgnoreCase)
            {
                ["selection"] = new SigmaSelection { Keywords = ["test"] }
            },
            Logsource = new SigmaLogsource { Product = "windows" }
        };
}
