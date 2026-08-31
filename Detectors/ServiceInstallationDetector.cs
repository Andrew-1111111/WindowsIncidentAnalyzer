using Microsoft.Extensions.Options;
using WindowsIncidentAnalyzer.Configuration;
using WindowsIncidentAnalyzer.Models;

namespace WindowsIncidentAnalyzer.Detectors;

public sealed class ServiceInstallationDetector(IOptions<DetectionRulesOptions> options) : DetectorBase
{
    private readonly ServiceInstallationOptions _options = options.Value.ServiceInstallation;

    public override string Name => "ServiceInstallation";

    public override string Description => "Detects new Windows services (Security 4697 and System 7045).";

    public override DetectionSeverity Severity => DetectionSeverity.Medium;

    public override bool IsEnabled => _options.Enabled;

    public override IReadOnlyList<int> RelevantEventIds => [4697, 7045];

    public override IEnumerable<SecurityFinding> Analyze(IEnumerable<WindowsEvent> events)
    {
        if (!IsEnabled)
        {
            yield break;
        }

        foreach (var evt in OfEventId(events, 4697, 7045))
        {
            yield return CreateFinding(
                "Windows service installed",
                $"Service '{evt.ServiceName}' was registered. Image: {evt.ProcessPath ?? evt.CommandLine ?? "(unknown)"}.",
                DetectionSeverity.Medium,
                evt,
                details: $"actor={evt.User}; startType={evt.GetProperty("ServiceStartType")}");
        }
    }
}
