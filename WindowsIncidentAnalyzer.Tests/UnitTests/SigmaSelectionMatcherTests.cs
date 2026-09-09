using WindowsIncidentAnalyzer.Sigma;
using WindowsIncidentAnalyzer.Sigma.Models;
using Xunit;

namespace WindowsIncidentAnalyzer.Tests.UnitTests;

public sealed class SigmaSelectionMatcherTests
{
    [Fact]
    public void Matches_KeywordInBlob_ReturnsTrueAndRecordsDetail()
    {
        var selection = new SigmaSelection { Keywords = ["malicious"] };
        var fields = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["_sigma_blob"] = "Process created with MALICIOUS payload"
        };
        var details = new List<SigmaFieldMatchDetail>();

        var matched = SigmaSelectionMatcher.Matches(selection, fields, details, "keyword_sel");

        Assert.True(matched);
        Assert.Single(details);
        Assert.Equal("keyword_sel", details[0].SelectionName);
        Assert.Equal("_sigma_blob", details[0].Field);
        Assert.Equal(SigmaFieldModifier.Contains, details[0].Modifier);
    }

    [Fact]
    public void Matches_KeywordMissingFromBlob_ReturnsFalse()
    {
        var selection = new SigmaSelection { Keywords = ["evil.exe"] };
        var fields = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["_sigma_blob"] = "benign activity"
        };

        Assert.False(SigmaSelectionMatcher.Matches(selection, fields));
    }

    [Fact]
    public void Matches_EmptySelection_ReturnsFalse()
    {
        var selection = new SigmaSelection();
        var fields = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["Image"] = @"C:\Windows\System32\cmd.exe"
        };

        Assert.False(SigmaSelectionMatcher.Matches(selection, fields));
    }

    [Theory]
    [InlineData(SigmaFieldModifier.Equals, "cmd.exe", "cmd.exe", true)]
    [InlineData(SigmaFieldModifier.Equals, "cmd.exe", "powershell.exe", false)]
    [InlineData(SigmaFieldModifier.Contains, "powershell -enc abc", "-enc", true)]
    [InlineData(SigmaFieldModifier.StartsWith, "C:\\Windows\\System32\\cmd.exe", "C:\\Windows", true)]
    [InlineData(SigmaFieldModifier.EndsWith, @"C:\Windows\System32\whoami.exe", @"\whoami.exe", true)]
    public void Matches_FieldModifier_ComparesExpected(
        SigmaFieldModifier modifier,
        string actual,
        string expected,
        bool shouldMatch)
    {
        var selection = new SigmaSelection
        {
            FieldMatches =
            [
                new SigmaFieldMatch
                {
                    Field = "Image",
                    Modifier = modifier,
                    Values = [expected]
                }
            ]
        };
        var fields = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["Image"] = actual
        };

        Assert.Equal(shouldMatch, SigmaSelectionMatcher.Matches(selection, fields));
    }

    [Fact]
    public void Matches_WildcardValue_UsesGlobSemantics()
    {
        var selection = new SigmaSelection
        {
            FieldMatches =
            [
                new SigmaFieldMatch
                {
                    Field = "CommandLine",
                    Modifier = SigmaFieldModifier.Equals,
                    Values = ["* -enc *"]
                }
            ]
        };
        var fields = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["CommandLine"] = "powershell.exe -enc SGVsbG8="
        };

        Assert.True(SigmaSelectionMatcher.Matches(selection, fields));
    }

    [Fact]
    public void Matches_RegexModifier_EvaluatesPattern()
    {
        var selection = new SigmaSelection
        {
            FieldMatches =
            [
                new SigmaFieldMatch
                {
                    Field = "CommandLine",
                    Modifier = SigmaFieldModifier.Regex,
                    Values = [@"(?i)powershell\.exe -enc"]
                }
            ]
        };
        var fields = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["CommandLine"] = "powershell.exe -enc payload"
        };

        Assert.True(SigmaSelectionMatcher.Matches(selection, fields));
    }

    [Fact]
    public void Matches_MultipleFieldMatches_RequiresAllFields()
    {
        var selection = new SigmaSelection
        {
            FieldMatches =
            [
                new SigmaFieldMatch { Field = "Image", Values = ["cmd.exe"] },
                new SigmaFieldMatch
                {
                    Field = "CommandLine",
                    Modifier = SigmaFieldModifier.Contains,
                    Values = ["whoami"]
                }
            ]
        };

        var bothMatch = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["Image"] = "cmd.exe",
            ["CommandLine"] = "cmd.exe /c whoami"
        };
        var oneMissing = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["Image"] = "cmd.exe",
            ["CommandLine"] = "cmd.exe /c hostname"
        };

        Assert.True(SigmaSelectionMatcher.Matches(selection, bothMatch));
        Assert.False(SigmaSelectionMatcher.Matches(selection, oneMissing));
    }

    [Fact]
    public void Matches_AlternateValues_MatchesAnyValue()
    {
        var selection = new SigmaSelection
        {
            FieldMatches =
            [
                new SigmaFieldMatch
                {
                    Field = "Image",
                    Values = ["powershell.exe", "cmd.exe"]
                }
            ]
        };
        var fields = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["Image"] = "cmd.exe"
        };

        Assert.True(SigmaSelectionMatcher.Matches(selection, fields));
    }

    [Fact]
    public void Matches_MissingField_ReturnsFalse()
    {
        var selection = new SigmaSelection
        {
            FieldMatches =
            [
                new SigmaFieldMatch { Field = "Image", Values = ["cmd.exe"] }
            ]
        };
        var fields = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["CommandLine"] = "cmd.exe"
        };

        Assert.False(SigmaSelectionMatcher.Matches(selection, fields));
    }

    [Fact]
    public void Matches_DottedFieldName_ResolvesViaMapper()
    {
        var selection = new SigmaSelection
        {
            FieldMatches =
            [
                new SigmaFieldMatch
                {
                    Field = "Event.System.EventID",
                    Values = ["4688"]
                }
            ]
        };
        var fields = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["EventID"] = "4688"
        };

        Assert.True(SigmaSelectionMatcher.Matches(selection, fields));
    }

    [Fact]
    public void Matches_FieldMatch_AddsDetailsForEachMatchedField()
    {
        var selection = new SigmaSelection
        {
            FieldMatches =
            [
                new SigmaFieldMatch
                {
                    Field = "Image",
                    Modifier = SigmaFieldModifier.EndsWith,
                    Values = [@"\cmd.exe"]
                }
            ]
        };
        var fields = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["Image"] = @"C:\Windows\System32\cmd.exe"
        };
        var details = new List<SigmaFieldMatchDetail>();

        Assert.True(SigmaSelectionMatcher.Matches(selection, fields, details, "proc"));
        Assert.Single(details);
        Assert.Equal("proc", details[0].SelectionName);
        Assert.Equal("Image", details[0].Field);
        Assert.Equal(@"C:\Windows\System32\cmd.exe", details[0].ActualValue);
        Assert.Equal(@"\cmd.exe", details[0].ExpectedValue);
        Assert.Equal(SigmaFieldModifier.EndsWith, details[0].Modifier);
    }
}
