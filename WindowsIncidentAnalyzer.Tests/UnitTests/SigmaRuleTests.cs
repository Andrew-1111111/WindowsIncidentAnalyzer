using WindowsIncidentAnalyzer.Models;
using WindowsIncidentAnalyzer.Sigma;
using Xunit;

namespace WindowsIncidentAnalyzer.Tests.UnitTests;

public sealed class SigmaRuleTests
{
    private const string WhoamiRule = """
        title: Whoami Execution
        id: 11111111-1111-1111-1111-111111111101
        status: test
        logsource:
          product: windows
          category: process_creation
        detection:
          selection:
            Image|endswith: '\whoami.exe'
          condition: selection
        level: medium
        """;

    [Fact]
    public void Parser_LoadsRuleWithSelectionsAndCondition()
    {
        var rules = new SigmaYamlParser().ParseDocuments(WhoamiRule, "sample.yml");
        Assert.Single(rules);
        Assert.Equal("Whoami Execution", rules[0].Title);
        Assert.Contains("selection", rules[0].Selections.Keys);
        Assert.Equal("selection", rules[0].Condition);
    }

    [Fact]
    public void Engine_MatchesWhoamiProcessCreationEvent_WithFieldDetails()
    {
        var rule = new SigmaYamlParser().ParseDocuments(WhoamiRule, "sample.yml").Single();
        var engine = new SigmaRuleEngine();
        var evt = new WindowsEvent
        {
            EventId = 4688,
            TimeCreatedUtc = DateTime.UtcNow,
            ProcessPath = @"C:\Windows\System32\whoami.exe",
            ProcessName = "whoami.exe",
            CommandLine = "whoami /all"
        };

        Assert.True(engine.TryMatch(rule, evt, out var match));
        Assert.NotNull(match);
        Assert.Contains("selection", match.MatchedSelections);
        Assert.Contains("Image", match.MatchedFields);
        Assert.Contains(@"C:\Windows\System32\whoami.exe", match.MatchedValues);
        Assert.Contains("Image endswith", match.Reason);
    }

    [Fact]
    public void ConditionEvaluator_SupportsAndOrExpressions()
    {
        var results = new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase)
        {
            ["selection_a"] = true,
            ["selection_b"] = false,
            ["selection_c"] = true
        };

        Assert.True(SigmaConditionEvaluator.Evaluate("selection_a and selection_c", results));
        Assert.True(SigmaConditionEvaluator.Evaluate("selection_a or selection_b", results));
        Assert.True(SigmaConditionEvaluator.Evaluate("1 of selection_*", results));
    }
}
