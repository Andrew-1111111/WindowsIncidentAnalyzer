using Microsoft.Extensions.Options;
using WindowsIncidentAnalyzer.Configuration;
using WindowsIncidentAnalyzer.Infrastructure;
using WindowsIncidentAnalyzer.Models;

namespace WindowsIncidentAnalyzer.Detectors;

public sealed class ProcessCreationDetector(IOptions<DetectionRulesOptions> options) : DetectorBase
{
    private readonly SuspiciousProcessCreationOptions _options = options.Value.SuspiciousProcessCreation;

    public override string Name => "SuspiciousProcessCreation";

    public override string Description => "Reviews process creation (4688 / Sysmon 1) for unusual paths, parents, and long command lines.";

    public override DetectionSeverity Severity => DetectionSeverity.Medium;

    public override bool IsEnabled => _options.Enabled;

    public override IReadOnlyList<int> RelevantEventIds => [4688, 1];

    public override IEnumerable<SecurityFinding> Analyze(IEnumerable<WindowsEvent> events)
    {
        if (!IsEnabled)
        {
            yield break;
        }

        foreach (var evt in events.Where(IsProcessCreate))
        {
            var path = evt.ProcessPath ?? evt.CommandLine ?? evt.ProcessName ?? string.Empty;
            var reasons = new List<string>();

            if (WindowsLocale.MatchesSuspiciousPath(path, _options.SuspiciousProcessPaths))
            {
                reasons.Add($"process path matches a configured suspicious location ({path})");
            }

            if (!string.IsNullOrEmpty(evt.CommandLine) && evt.CommandLine.Length >= _options.LongCommandLineLength)
            {
                reasons.Add($"command line length {evt.CommandLine.Length} exceeds {_options.LongCommandLineLength}");
            }

            var parent = evt.ParentProcessName ?? string.Empty;
            var child = evt.ProcessName ?? string.Empty;
            var parentChild = _options.SuspiciousParentChild.FirstOrDefault(r =>
                parent.Equals(r.Parent, StringComparison.OrdinalIgnoreCase) &&
                child.Equals(r.Child, StringComparison.OrdinalIgnoreCase));
            if (parentChild != null)
            {
                reasons.Add($"unusual parent/child pair {parentChild.Parent} -> {parentChild.Child}");
            }

            if (reasons.Count == 0)
            {
                continue;
            }

            yield return CreateFinding(
                "Suspicious process creation",
                string.Join("; ", reasons),
                reasons.Count > 1 ? DetectionSeverity.High : DetectionSeverity.Medium,
                evt,
                details: $"image={path}; parent={evt.ParentProcessName}; cmd={Trim(evt.CommandLine, 400)}");
        }
    }

    private static bool IsProcessCreate(WindowsEvent evt)
    {
        if (evt.EventId == 4688)
        {
            return true;
        }

        return evt.EventId == 1 && evt.ProviderName?.Contains("Sysmon", StringComparison.OrdinalIgnoreCase) == true;
    }

    private static string? Trim(string? value, int max) =>
        string.IsNullOrEmpty(value) ? value : value.Length <= max ? value : value[..max] + "...";
}
