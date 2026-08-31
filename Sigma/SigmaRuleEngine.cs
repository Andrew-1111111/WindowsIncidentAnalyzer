using WindowsIncidentAnalyzer.Models;
using WindowsIncidentAnalyzer.Sigma.Models;

namespace WindowsIncidentAnalyzer.Sigma;

public sealed class SigmaRuleEngine
{
    public bool TryMatch(SigmaRule rule, WindowsEvent evt, out SigmaMatchResult? matchResult)
    {
        matchResult = null;
        if (!SigmaLogsourceCatalog.MatchesEvent(rule, evt))
        {
            return false;
        }

        var fields = SigmaEventMapper.Map(evt);
        var results = new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase);
        var fieldMatches = new List<SigmaFieldMatchDetail>();

        foreach (var (name, selection) in rule.Selections)
        {
            var selectionDetails = new List<SigmaFieldMatchDetail>();
            var matched = SigmaSelectionMatcher.Matches(selection, fields, selectionDetails, name);
            results[name] = matched;
            if (matched)
            {
                fieldMatches.AddRange(selectionDetails);
            }
        }

        if (!SigmaConditionEvaluator.Evaluate(rule.Condition, results))
        {
            return false;
        }

        var matchedSelections = results.Where(pair => pair.Value).Select(pair => pair.Key).ToList();
        var activeMatches = fieldMatches
            .Where(match => matchedSelections.Contains(match.SelectionName, StringComparer.OrdinalIgnoreCase))
            .ToList();

        matchResult = new SigmaMatchResult
        {
            MatchedSelections = matchedSelections,
            FieldMatches = activeMatches,
            Reason = SigmaMatchReasonBuilder.Build(rule.Condition, matchedSelections, activeMatches)
        };
        return true;
    }
}
