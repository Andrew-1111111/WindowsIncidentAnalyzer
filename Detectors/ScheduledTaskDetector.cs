using Microsoft.Extensions.Options;
using WindowsIncidentAnalyzer.Configuration;
using WindowsIncidentAnalyzer.Infrastructure;
using WindowsIncidentAnalyzer.Models;

namespace WindowsIncidentAnalyzer.Detectors;

public sealed class ScheduledTaskDetector(IOptions<DetectionRulesOptions> options) : DetectorBase
{
    private readonly SuspiciousScheduledTaskOptions _options = options.Value.SuspiciousScheduledTask;

    public override string Name => "SuspiciousScheduledTask";

    public override string Description => "Reviews scheduled task create/update/delete events (4698/4702/4699) for unusual paths.";

    public override DetectionSeverity Severity => DetectionSeverity.Medium;

    public override bool IsEnabled => _options.Enabled;

    public override IReadOnlyList<int> RelevantEventIds => [4698, 4702, 4699];

    public override IEnumerable<SecurityFinding> Analyze(IEnumerable<WindowsEvent> events)
    {
        if (!IsEnabled)
        {
            yield break;
        }

        foreach (var evt in OfEventId(events, 4698, 4702, 4699))
        {
            var xml = evt.CommandLine ?? evt.GetProperty("TaskContent") ?? evt.GetProperty("TaskContentNew") ?? evt.RawXml ?? string.Empty;
            var suspicious = WindowsLocale.MatchingSuspiciousPaths(xml, _options.SuspiciousPaths).ToList();
            var action = evt.EventId switch
            {
                4698 => "created",
                4702 => "updated",
                4699 => "deleted",
                _ => "modified"
            };

            var severity = suspicious.Count > 0 ? DetectionSeverity.High : DetectionSeverity.Medium;
            var extra = suspicious.Count > 0
                ? $" Task XML references suspicious path(s): {string.Join(", ", suspicious)}."
                : string.Empty;

            yield return CreateFinding(
                $"Scheduled task {action}",
                $"Task '{evt.TaskName ?? "(unnamed)"}' was {action} by '{evt.User}'.{extra}",
                severity,
                evt,
                details: Trim(xml, 800));
        }
    }

    private static string Trim(string value, int max) =>
        value.Length <= max ? value : value[..max] + "...";
}
