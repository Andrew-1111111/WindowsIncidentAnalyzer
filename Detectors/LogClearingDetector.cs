using Microsoft.Extensions.Options;
using WindowsIncidentAnalyzer.Configuration;
using WindowsIncidentAnalyzer.Models;

namespace WindowsIncidentAnalyzer.Detectors;

public sealed class LogClearingDetector(IOptions<DetectionRulesOptions> options) : DetectorBase
{
    private readonly LogClearingOptions _options = options.Value.LogClearing;

    public override string Name => "LogClearing";

    public override string Description => "Detects Security log clearing (1102) and event-channel clearing (104).";

    public override DetectionSeverity Severity => DetectionSeverity.Critical;

    public override bool IsEnabled => _options.Enabled;

    public override IReadOnlyList<int> RelevantEventIds => [104, 1102];

    public override IEnumerable<SecurityFinding> Analyze(IEnumerable<WindowsEvent> events)
    {
        if (!IsEnabled)
        {
            yield break;
        }

        foreach (var evt in OfEventId(events, 104, 1102))
        {
            if (evt.EventId == 104 &&
                !(evt.ProviderName?.Contains("Eventlog", StringComparison.OrdinalIgnoreCase) ?? false))
            {
                continue;
            }

            yield return CreateFinding(
                evt.EventId == 1102 ? "Security event log was cleared" : "Windows event channel was cleared",
                $"An event log on '{evt.ComputerName}' was cleared by '{evt.User}' at {evt.TimeCreatedUtc:u}.",
                evt.EventId == 1102 ? DetectionSeverity.Critical : DetectionSeverity.High,
                evt,
                details: $"user={evt.User}; domain={evt.Domain}; computer={evt.ComputerName}; time={evt.TimeCreatedUtc:o}");
        }
    }
}
