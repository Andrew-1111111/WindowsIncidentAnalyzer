using System.Collections.Concurrent;
using Microsoft.Extensions.Options;
using WindowsIncidentAnalyzer.Configuration;
using WindowsIncidentAnalyzer.Infrastructure;
using WindowsIncidentAnalyzer.Models;
using WindowsIncidentAnalyzer.Services;
using WindowsIncidentAnalyzer.Sigma;
using WindowsIncidentAnalyzer.Sigma.Models;

namespace WindowsIncidentAnalyzer.Detectors;

public sealed class SigmaRuleDetector(
    ISigmaRuleService sigmaRules,
    SigmaRuleEngine engine,
    IOptions<DetectionRulesOptions> options,
    IOptions<AnalyzerOptions> analyzerOptions) : DetectorBase
{
    public override string Name => "SigmaRules";

    public override string Description => "Evaluates loaded Sigma detection rules against normalized Windows events.";

    public override DetectionSeverity Severity => DetectionSeverity.Medium;

    public override bool IsEnabled => options.Value.SigmaRules.Enabled;

    public override IReadOnlyList<int>? RelevantEventIds
    {
        get
        {
            var ids = SigmaLogsourceCatalog.AggregateEventIds(sigmaRules.GetRules());
            return ids.Count == 0 ? null : ids;
        }
    }

    public override IEnumerable<SecurityFinding> Analyze(IEnumerable<WindowsEvent> events)
    {
        if (!IsEnabled)
        {
            return [];
        }

        var rules = sigmaRules.GetRules();
        if (rules.Count == 0)
        {
            return [];
        }

        var eventList = events as IReadOnlyList<WindowsEvent> ?? events.ToList();
        if (eventList.Count == 0)
        {
            return [];
        }

        var analyzer = analyzerOptions.Value;
        var findings = new ConcurrentBag<SecurityFinding>();

        void EvaluateEvent(WindowsEvent evt)
        {
            var fields = SigmaEventMapper.Map(evt);
            foreach (var rule in rules)
            {
                if (!engine.TryMatch(rule, evt, fields, out var match) || match == null)
                {
                    continue;
                }

                findings.Add(CreateFinding(
                    $"[Sigma] {rule.Title}",
                    string.IsNullOrWhiteSpace(rule.Description)
                        ? $"Sigma rule matched ({rule.Id ?? Path.GetFileName(rule.SourcePath)})."
                        : rule.Description,
                    rule.Severity,
                    evt,
                    details: BuildLegacyDetails(rule, match),
                    configureContext: ctx => ApplySigmaContext(ctx, rule, match)));
            }
        }

        if (ParallelAnalysis.ShouldUseParallel(analyzer.MaxDegreeOfParallelism, eventList.Count))
        {
            Parallel.ForEach(eventList, ParallelAnalysis.CreateCpuBoundOptions(analyzer), EvaluateEvent);
        }
        else
        {
            foreach (var evt in eventList)
            {
                EvaluateEvent(evt);
            }
        }

        return findings
            .OrderByDescending(f => f.Severity)
            .ThenBy(f => f.TimeUtc)
            .ToList();
    }

    private static void ApplySigmaContext(FindingContext context, SigmaRule rule, SigmaMatchResult match)
    {
        context.RuleId = rule.Id ?? Path.GetFileName(rule.SourcePath);
        context.RuleTitle = rule.Title;
        context.Category = rule.Logsource.Category ?? rule.Logsource.Service ?? "sigma";
        context.Severity = rule.Severity;
        context.SigmaId = rule.Id;
        context.SigmaStatus = rule.Status;
        context.Condition = rule.Condition;
        context.MatchedSelection = string.Join(", ", match.MatchedSelections);
        context.MatchedFields = match.MatchedFields.ToList();
        context.MatchedValues = match.MatchedValues.ToList();
        context.Reason = match.Reason;
        SigmaMitreTagParser.Apply(rule.Tags, context);
    }

    private static string BuildLegacyDetails(SigmaRule rule, SigmaMatchResult match)
    {
        var tags = rule.Tags.Count == 0 ? string.Empty : string.Join(", ", rule.Tags.Take(8));
        return
            $"sigmaId={rule.Id}; status={rule.Status}; source={rule.SourcePath}; tags={tags}; reason={match.Reason}";
    }
}
