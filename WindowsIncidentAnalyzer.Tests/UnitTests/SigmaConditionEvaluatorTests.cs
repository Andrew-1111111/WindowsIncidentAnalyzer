using WindowsIncidentAnalyzer.Sigma;
using Xunit;

namespace WindowsIncidentAnalyzer.Tests.UnitTests;

public sealed class SigmaConditionEvaluatorTests
{
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void Evaluate_EmptyCondition_ReturnsFalse(string? condition)
    {
        var results = new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase)
        {
            ["selection"] = true
        };

        Assert.False(SigmaConditionEvaluator.Evaluate(condition!, results));
    }

    [Fact]
    public void Evaluate_SingleSelection_ReplacesNameWithBoolean()
    {
        var results = new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase)
        {
            ["selection"] = true
        };

        Assert.True(SigmaConditionEvaluator.Evaluate("selection", results));
    }

    [Fact]
    public void Evaluate_AndOrNot_SupportsBooleanLogic()
    {
        var results = new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase)
        {
            ["selection_a"] = true,
            ["selection_b"] = false,
            ["selection_c"] = true
        };

        Assert.True(SigmaConditionEvaluator.Evaluate("selection_a and selection_c", results));
        Assert.True(SigmaConditionEvaluator.Evaluate("selection_a or selection_b", results));
        Assert.False(SigmaConditionEvaluator.Evaluate("selection_a and selection_b", results));
        Assert.True(SigmaConditionEvaluator.Evaluate("not selection_b", results));
        Assert.False(SigmaConditionEvaluator.Evaluate("not selection_a", results));
    }

    [Fact]
    public void Evaluate_Parentheses_ControlsPrecedence()
    {
        var results = new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase)
        {
            ["a"] = true,
            ["b"] = false,
            ["c"] = false
        };

        Assert.False(SigmaConditionEvaluator.Evaluate("(a or b) and c", results));
        Assert.True(SigmaConditionEvaluator.Evaluate("a or (b and c)", results));
    }

    [Fact]
    public void Evaluate_OneOfWildcard_CountsMatchingSelections()
    {
        var results = new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase)
        {
            ["selection_a"] = true,
            ["selection_b"] = false,
            ["selection_c"] = true
        };

        Assert.True(SigmaConditionEvaluator.Evaluate("1 of selection_*", results));
        Assert.True(SigmaConditionEvaluator.Evaluate("2 of selection_*", results));
        Assert.False(SigmaConditionEvaluator.Evaluate("3 of selection_*", results));
    }

    [Fact]
    public void Evaluate_AllOfWildcard_RequiresEveryMatch()
    {
        var results = new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase)
        {
            ["filter_a"] = true,
            ["filter_b"] = true,
            ["filter_c"] = false
        };

        Assert.False(SigmaConditionEvaluator.Evaluate("all of filter_*", results));

        results["filter_c"] = true;
        Assert.True(SigmaConditionEvaluator.Evaluate("all of filter_*", results));
    }

    [Fact]
    public void Evaluate_LongerSelectionNamesReplacedFirst()
    {
        var results = new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase)
        {
            ["selection"] = false,
            ["selection_extra"] = true
        };

        Assert.True(SigmaConditionEvaluator.Evaluate("selection_extra", results));
        Assert.False(SigmaConditionEvaluator.Evaluate("selection", results));
    }

    [Fact]
    public void Evaluate_IsCaseInsensitive()
    {
        var results = new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase)
        {
            ["Selection_A"] = true,
            ["selection_b"] = false
        };

        Assert.True(SigmaConditionEvaluator.Evaluate("SELECTION_A AND NOT selection_b", results));
    }

    [Fact]
    public void Evaluate_UnknownSelectionName_TreatedAsFalse()
    {
        var results = new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase)
        {
            ["known"] = true
        };

        Assert.False(SigmaConditionEvaluator.Evaluate("known and missing", results));
    }
}
