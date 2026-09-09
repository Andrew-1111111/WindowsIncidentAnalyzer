using WindowsIncidentAnalyzer.Sigma;
using WindowsIncidentAnalyzer.Sigma.Models;
using Xunit;

namespace WindowsIncidentAnalyzer.Tests.UnitTests;

public sealed class SigmaMatchReasonBuilderTests
{
    [Fact]
    public void Build_ConditionOnly_IncludesQuotedCondition()
    {
        var reason = SigmaMatchReasonBuilder.Build("selection_a and selection_b", [], []);

        Assert.Equal("condition=\"selection_a and selection_b\"", reason);
    }

    [Fact]
    public void Build_MatchedSelections_AppendsSelectionList()
    {
        var reason = SigmaMatchReasonBuilder.Build(
            "selection",
            ["selection", "filter"],
            []);

        Assert.Equal("condition=\"selection\"; matchedSelection=selection,filter", reason);
    }

    [Fact]
    public void Build_FieldMatches_DescribesModifierAndValues()
    {
        var reason = SigmaMatchReasonBuilder.Build(
            string.Empty,
            [],
            [
                new SigmaFieldMatchDetail
                {
                    Field = "Image",
                    Modifier = SigmaFieldModifier.EndsWith,
                    ExpectedValue = @"\cmd.exe",
                    ActualValue = @"C:\Windows\System32\cmd.exe"
                },
                new SigmaFieldMatchDetail
                {
                    Field = "CommandLine",
                    Modifier = SigmaFieldModifier.Contains,
                    ExpectedValue = "-enc",
                    ActualValue = "powershell -enc payload"
                }
            ]);

        Assert.Contains("Image endswith \"\\cmd.exe\" (actual=\"C:\\Windows\\System32\\cmd.exe\")", reason);
        Assert.Contains("CommandLine contains \"-enc\" (actual=\"powershell -enc payload\")", reason);
    }

    [Fact]
    public void Build_FullMatchReason_CombinesAllSections()
    {
        var reason = SigmaMatchReasonBuilder.Build(
            "selection",
            ["selection"],
            [
                new SigmaFieldMatchDetail
                {
                    Field = "Image",
                    Modifier = SigmaFieldModifier.Equals,
                    ExpectedValue = "cmd.exe",
                    ActualValue = "cmd.exe"
                }
            ]);

        Assert.StartsWith("condition=\"selection\"; matchedSelection=selection;", reason);
        Assert.Contains("Image equals \"cmd.exe\" (actual=\"cmd.exe\")", reason);
    }

    [Theory]
    [InlineData(SigmaFieldModifier.Regex, "matches")]
    [InlineData(SigmaFieldModifier.StartsWith, "startswith")]
    [InlineData(SigmaFieldModifier.EndsWith, "endswith")]
    [InlineData(SigmaFieldModifier.Contains, "contains")]
    [InlineData(SigmaFieldModifier.Equals, "equals")]
    public void Build_DescribesAllModifiers(SigmaFieldModifier modifier, string expectedWord)
    {
        var reason = SigmaMatchReasonBuilder.Build(
            string.Empty,
            [],
            [
                new SigmaFieldMatchDetail
                {
                    Field = "Field",
                    Modifier = modifier,
                    ExpectedValue = "x",
                    ActualValue = "x"
                }
            ]);

        Assert.Contains($"Field {expectedWord}", reason);
    }

    [Fact]
    public void Build_EmptyInput_ReturnsEmptyString()
    {
        Assert.Equal(string.Empty, SigmaMatchReasonBuilder.Build(string.Empty, [], []));
    }
}
