using System.Text;
using WindowsIncidentAnalyzer.Sigma.Models;

namespace WindowsIncidentAnalyzer.Sigma;

public static class SigmaMatchReasonBuilder
{
    public static string Build(
        string condition,
        IReadOnlyList<string> matchedSelections,
        IReadOnlyList<SigmaFieldMatchDetail> fieldMatches)
    {
        var builder = new StringBuilder();
        if (!string.IsNullOrWhiteSpace(condition))
        {
            builder.Append("condition=\"").Append(condition).Append('"');
        }

        if (matchedSelections.Count > 0)
        {
            if (builder.Length > 0)
            {
                builder.Append("; ");
            }

            builder.Append("matchedSelection=").Append(string.Join(",", matchedSelections));
        }

        foreach (var match in fieldMatches)
        {
            if (builder.Length > 0)
            {
                builder.Append("; ");
            }

            builder.Append(match.Field)
                .Append(' ')
                .Append(DescribeModifier(match.Modifier))
                .Append(" \"")
                .Append(match.ExpectedValue)
                .Append("\" (actual=\"")
                .Append(match.ActualValue)
                .Append("\")");
        }

        return builder.ToString();
    }

    private static string DescribeModifier(SigmaFieldModifier modifier) => modifier switch
    {
        SigmaFieldModifier.Contains => "contains",
        SigmaFieldModifier.StartsWith => "startswith",
        SigmaFieldModifier.EndsWith => "endswith",
        SigmaFieldModifier.Regex => "matches",
        _ => "equals"
    };
}
