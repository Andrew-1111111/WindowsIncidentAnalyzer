using System.Text.RegularExpressions;

namespace WindowsIncidentAnalyzer.Sigma;

public static class SigmaConditionEvaluator
{
    public static bool Evaluate(string condition, IReadOnlyDictionary<string, bool> selectionResults)
    {
        if (string.IsNullOrWhiteSpace(condition))
        {
            return false;
        }

        var expression = condition.Trim();
        expression = ExpandOfExpressions(expression, selectionResults, requireAll: false);
        expression = ExpandOfExpressions(expression, selectionResults, requireAll: true);

        foreach (var (name, matched) in selectionResults.OrderByDescending(x => x.Key.Length))
        {
            expression = Regex.Replace(
                expression,
                $@"\b{Regex.Escape(name)}\b",
                matched ? "true" : "false",
                RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        }

        return BooleanExpressionEvaluator.Evaluate(expression);
    }

    private static string ExpandOfExpressions(
        string expression,
        IReadOnlyDictionary<string, bool> selectionResults,
        bool requireAll)
    {
        var pattern = requireAll
            ? @"\ball\s+of\s+([\w*?-]+)"
            : @"\b(\d+)\s+of\s+([\w*?-]+)";
        return Regex.Replace(
            expression,
            pattern,
            match =>
            {
                if (requireAll)
                {
                    var prefix = match.Groups[1].Value;
                    var keys = ResolveSelectionNames(prefix, selectionResults);
                    return keys.Count > 0 && keys.All(key => selectionResults[key]) ? "true" : "false";
                }

                var count = int.Parse(match.Groups[1].Value);
                var wildcard = match.Groups[2].Value;
                var names = ResolveSelectionNames(wildcard, selectionResults);
                var hits = names.Count(name => selectionResults[name]);
                return hits >= count ? "true" : "false";
            },
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
    }

    private static List<string> ResolveSelectionNames(string pattern, IReadOnlyDictionary<string, bool> selectionResults)
    {
        if (pattern.Contains('*', StringComparison.Ordinal))
        {
            var regex = "^" + Regex.Escape(pattern).Replace("\\*", ".*", StringComparison.Ordinal) + "$";
            return selectionResults.Keys
                .Where(name => Regex.IsMatch(name, regex, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant))
                .ToList();
        }

        return selectionResults.ContainsKey(pattern) ? [pattern] : [];
    }
}

internal static class BooleanExpressionEvaluator
{
    public static bool Evaluate(string expression)
    {
        var tokens = Tokenize(expression);
        var index = 0;
        var result = ParseOr(tokens, ref index);
        return result;
    }

    private static List<string> Tokenize(string expression)
    {
        var tokens = new List<string>();
        foreach (Match match in Regex.Matches(expression, @"true|false|\(|\)|\band\b|\bor\b|\bnot\b", RegexOptions.IgnoreCase))
        {
            tokens.Add(match.Value.ToLowerInvariant());
        }

        return tokens;
    }

    private static bool ParseOr(IReadOnlyList<string> tokens, ref int index)
    {
        var value = ParseAnd(tokens, ref index);
        while (index < tokens.Count && tokens[index] == "or")
        {
            index++;
            value |= ParseAnd(tokens, ref index);
        }

        return value;
    }

    private static bool ParseAnd(IReadOnlyList<string> tokens, ref int index)
    {
        var value = ParseUnary(tokens, ref index);
        while (index < tokens.Count && tokens[index] == "and")
        {
            index++;
            value &= ParseUnary(tokens, ref index);
        }

        return value;
    }

    private static bool ParseUnary(IReadOnlyList<string> tokens, ref int index)
    {
        if (index < tokens.Count && tokens[index] == "not")
        {
            index++;
            return !ParseUnary(tokens, ref index);
        }

        if (index < tokens.Count && tokens[index] == "(")
        {
            index++;
            var value = ParseOr(tokens, ref index);
            if (index < tokens.Count && tokens[index] == ")")
            {
                index++;
            }

            return value;
        }

        if (index < tokens.Count)
        {
            return tokens[index++] == "true";
        }

        return false;
    }
}
