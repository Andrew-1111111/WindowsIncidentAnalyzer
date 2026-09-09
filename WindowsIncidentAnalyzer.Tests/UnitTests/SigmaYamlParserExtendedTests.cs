using WindowsIncidentAnalyzer.Models;
using WindowsIncidentAnalyzer.Sigma;
using WindowsIncidentAnalyzer.Sigma.Models;
using Xunit;

namespace WindowsIncidentAnalyzer.Tests.UnitTests;

public sealed class SigmaYamlParserExtendedTests
{
    private const string ValidRuleA = """
        title: Rule Alpha
        id: 11111111-1111-1111-1111-111111111101
        status: test
        author: tester
        logsource:
          product: windows
          category: process_creation
        detection:
          selection:
            Image|endswith: '\cmd.exe'
          condition: selection
        level: high
        tags:
          - attack.execution
          - attack.t1059
        """;

    private const string ValidRuleB = """
        title: Rule Beta
        id: 22222222-2222-2222-2222-222222222202
        logsource:
          product: windows
          category: ps_script
          service: powershell
        detection:
          selection_keywords: suspicious
          selection_fields:
            ScriptBlockText|contains:
              - Invoke-Mimikatz
              - DownloadString
            ScriptBlockText|re: '(?i)encodedcommand'
          condition: selection_keywords or selection_fields
        level: critical
        """;

    [Fact]
    public void ParseDocuments_MultiDocumentYaml_ReturnsAllValidRules()
    {
        var yaml = ValidRuleA + "\n---\n" + ValidRuleB;
        var rules = new SigmaYamlParser().ParseDocuments(yaml, "multi.yml");

        Assert.Equal(2, rules.Count);
        Assert.Equal("Rule Alpha", rules[0].Title);
        Assert.Equal("Rule Beta", rules[1].Title);
        Assert.Equal(DetectionSeverity.High, rules[0].Severity);
        Assert.Equal(DetectionSeverity.Critical, rules[1].Severity);
    }

    [Fact]
    public void ParseDocuments_FieldModifiers_AreParsedCorrectly()
    {
        const string yaml = """
            title: Modifier Rule
            logsource:
              product: windows
              category: process_creation
            detection:
              selection:
                Image|contains: 'cmd'
                CommandLine|startswith: 'powershell'
                ParentImage|endswith: 'explorer.exe'
                User|re: '.*admin.*'
              condition: selection
            """;

        var rule = new SigmaYamlParser().ParseDocuments(yaml, "modifiers.yml").Single();
        var matches = rule.Selections["selection"].FieldMatches;

        Assert.Equal(4, matches.Count);
        Assert.Contains(matches, m => m.Field == "Image" && m.Modifier == SigmaFieldModifier.Contains);
        Assert.Contains(matches, m => m.Field == "CommandLine" && m.Modifier == SigmaFieldModifier.StartsWith);
        Assert.Contains(matches, m => m.Field == "ParentImage" && m.Modifier == SigmaFieldModifier.EndsWith);
        Assert.Contains(matches, m => m.Field == "User" && m.Modifier == SigmaFieldModifier.Regex);
    }

    [Fact]
    public void ParseDocuments_KeywordSelections_SupportStringAndList()
    {
        const string yaml = """
            title: Keyword Rule
            logsource:
              product: windows
              category: process_creation
            detection:
              selection_string: evil
              selection_list:
                - alpha
                - beta
              condition: selection_string or selection_list
            """;

        var rule = new SigmaYamlParser().ParseDocuments(yaml, "keywords.yml").Single();

        Assert.Equal(["evil"], rule.Selections["selection_string"].Keywords);
        Assert.Equal(["alpha", "beta"], rule.Selections["selection_list"].Keywords);
    }

    [Fact]
    public void ParseDocuments_SkipsMalformedAndIncompleteDocuments()
    {
        const string yaml = """
            title: Good Rule
            logsource:
              product: windows
              category: process_creation
            detection:
              selection:
                Image: cmd.exe
              condition: selection
            ---
            title: Missing Detection
            logsource:
              product: windows
            ---
            not: valid: yaml: [[[
            ---
            title: Missing Condition
            logsource:
              product: windows
            detection:
              selection:
                Image: cmd.exe
            ---
            logsource:
              product: windows
            detection:
              selection:
                Image: cmd.exe
              condition: selection
            """;

        var rules = new SigmaYamlParser().ParseDocuments(yaml, "mixed.yml");

        Assert.Single(rules);
        Assert.Equal("Good Rule", rules[0].Title);
    }

    [Fact]
    public void ParseDocuments_PopulatesLogsourceAndRelevantEventIds()
    {
        var rule = new SigmaYamlParser().ParseDocuments(ValidRuleA, "alpha.yml").Single();

        Assert.Equal("windows", rule.Logsource.Product);
        Assert.Equal("process_creation", rule.Logsource.Category);
        Assert.Contains(1, rule.RelevantEventIds);
        Assert.Contains(4688, rule.RelevantEventIds);
    }

    [Fact]
    public void ParseDocuments_PreservesMetadataAndTags()
    {
        var rule = new SigmaYamlParser().ParseDocuments(ValidRuleA, "alpha.yml").Single();

        Assert.Equal("11111111-1111-1111-1111-111111111101", rule.Id);
        Assert.Equal("test", rule.Status);
        Assert.Equal("tester", rule.Author);
        Assert.Equal("alpha.yml", rule.SourcePath);
        Assert.Contains("attack.execution", rule.Tags);
        Assert.Contains("attack.t1059", rule.Tags);
    }

    [Theory]
    [InlineData("informational", DetectionSeverity.Info)]
    [InlineData("info", DetectionSeverity.Info)]
    [InlineData("low", DetectionSeverity.Low)]
    [InlineData("medium", DetectionSeverity.Medium)]
    [InlineData("high", DetectionSeverity.High)]
    [InlineData("critical", DetectionSeverity.Critical)]
    [InlineData(null, DetectionSeverity.Medium)]
    public void ParseDocuments_MapsSeverityLevels(string? level, DetectionSeverity expected)
    {
        var yaml = $"""
            title: Severity Rule
            logsource:
              product: windows
              category: process_creation
            detection:
              selection:
                Image: cmd.exe
              condition: selection
            level: {level ?? "medium"}
            """;

        var rule = new SigmaYamlParser().ParseDocuments(yaml, "severity.yml").Single();
        Assert.Equal(expected, rule.Severity);
    }
}
