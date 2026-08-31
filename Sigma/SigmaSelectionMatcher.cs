using System.Text.RegularExpressions;
using WindowsIncidentAnalyzer.Sigma.Models;

namespace WindowsIncidentAnalyzer.Sigma;

public static class SigmaSelectionMatcher
{
    public static bool Matches(
        SigmaSelection selection,
        IReadOnlyDictionary<string, string> fields,
        ICollection<SigmaFieldMatchDetail>? matchDetails = null,
        string selectionName = "")
    {
        if (selection.Keywords.Count > 0)
        {
            var blob = fields.TryGetValue("_sigma_blob", out var value) ? value : string.Empty;
            var matchedKeyword = selection.Keywords.FirstOrDefault(keyword =>
                !string.IsNullOrWhiteSpace(keyword) &&
                blob.Contains(keyword, StringComparison.OrdinalIgnoreCase));

            if (matchedKeyword == null)
            {
                return false;
            }

            matchDetails?.Add(new SigmaFieldMatchDetail
            {
                SelectionName = selectionName,
                Field = "_sigma_blob",
                ActualValue = matchedKeyword,
                ExpectedValue = matchedKeyword,
                Modifier = SigmaFieldModifier.Contains
            });
            return true;
        }

        if (selection.FieldMatches.Count == 0)
        {
            return false;
        }

        var allMatched = true;
        foreach (var match in selection.FieldMatches)
        {
            if (!TryFieldMatch(match, fields, out var actualValue, out var expectedValue))
            {
                allMatched = false;
                continue;
            }

            matchDetails?.Add(new SigmaFieldMatchDetail
            {
                SelectionName = selectionName,
                Field = match.Field,
                ActualValue = actualValue,
                ExpectedValue = expectedValue,
                Modifier = match.Modifier
            });
        }

        return allMatched;
    }

    private static bool TryFieldMatch(
        SigmaFieldMatch match,
        IReadOnlyDictionary<string, string> fields,
        out string actualValue,
        out string expectedValue)
    {
        actualValue = string.Empty;
        expectedValue = string.Empty;
        var actual = SigmaEventMapper.ResolveField(fields, match.Field);
        if (actual == null)
        {
            return false;
        }

        foreach (var expected in match.Values)
        {
            if (!Compare(actual, expected, match.Modifier))
            {
                continue;
            }

            actualValue = actual;
            expectedValue = expected;
            return true;
        }

        return false;
    }

    private static bool Compare(string actual, string expected, SigmaFieldModifier modifier)
    {
        if (expected.Contains('*', StringComparison.Ordinal))
        {
            var pattern = "^" + Regex.Escape(expected).Replace("\\*", ".*", StringComparison.Ordinal) + "$";
            return Regex.IsMatch(actual, pattern, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        }

        return modifier switch
        {
            SigmaFieldModifier.Contains => actual.Contains(expected, StringComparison.OrdinalIgnoreCase),
            SigmaFieldModifier.StartsWith => actual.StartsWith(expected, StringComparison.OrdinalIgnoreCase),
            SigmaFieldModifier.EndsWith => actual.EndsWith(expected, StringComparison.OrdinalIgnoreCase),
            SigmaFieldModifier.Regex => Regex.IsMatch(actual, expected, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant),
            _ => actual.Equals(expected, StringComparison.OrdinalIgnoreCase)
        };
    }
}
