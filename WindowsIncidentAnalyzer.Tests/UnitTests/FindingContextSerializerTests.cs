using WindowsIncidentAnalyzer.Infrastructure;
using WindowsIncidentAnalyzer.Models;
using Xunit;

namespace WindowsIncidentAnalyzer.Tests.UnitTests;

public sealed class FindingContextSerializerTests
{
    [Fact]
    public void Serialize_Null_ReturnsNull()
    {
        Assert.Null(FindingContextSerializer.Serialize(null));
    }

    [Fact]
    public void Deserialize_NullOrWhitespace_ReturnsEmptyContext()
    {
        Assert.NotNull(FindingContextSerializer.Deserialize(null));
        Assert.NotNull(FindingContextSerializer.Deserialize("   "));
        Assert.Null(FindingContextSerializer.Deserialize("   ").RuleId);
    }

    [Fact]
    public void Deserialize_CorruptJson_ReturnsEmptyContext()
    {
        var context = FindingContextSerializer.Deserialize("{not-json");
        Assert.NotNull(context);
        Assert.Null(context.RuleId);
        Assert.Empty(context.MitreTags);
    }

    [Fact]
    public void RoundTrip_PreservesKeyFieldsAndEnums()
    {
        var original = new FindingContext
        {
            RuleId = "rule-1",
            RuleTitle = "Title",
            Severity = DetectionSeverity.High,
            RequestedSeverity = DetectionSeverity.Critical,
            EventId = 4688,
            MitreTechnique = "T1059",
            MitreTags = ["attack.execution", "attack.t1059"],
            MatchedFields = ["Image"],
            MatchedValues = [@"C:\Windows\System32\cmd.exe"],
            CategoryMatchesEvent = true,
            SeverityMatchesEvent = false
        };

        var json = FindingContextSerializer.Serialize(original);
        Assert.NotNull(json);
        Assert.Contains("\"severity\":\"High\"", json, StringComparison.Ordinal);

        var restored = FindingContextSerializer.Deserialize(json);
        Assert.Equal(original.RuleId, restored.RuleId);
        Assert.Equal(original.RuleTitle, restored.RuleTitle);
        Assert.Equal(original.Severity, restored.Severity);
        Assert.Equal(original.RequestedSeverity, restored.RequestedSeverity);
        Assert.Equal(original.EventId, restored.EventId);
        Assert.Equal(original.MitreTechnique, restored.MitreTechnique);
        Assert.Equal(original.MitreTags, restored.MitreTags);
        Assert.Equal(original.MatchedFields, restored.MatchedFields);
        Assert.Equal(original.MatchedValues, restored.MatchedValues);
        Assert.True(restored.CategoryMatchesEvent);
        Assert.False(restored.SeverityMatchesEvent);
    }
}
