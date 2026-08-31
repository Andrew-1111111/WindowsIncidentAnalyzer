using WindowsIncidentAnalyzer.Models;

namespace WindowsIncidentAnalyzer.Detectors;

public interface IDetectionRule
{
    string Name { get; }

    string Description { get; }

    DetectionSeverity Severity { get; }

    bool IsEnabled { get; }

    IReadOnlyList<int>? RelevantEventIds { get; }

    IEnumerable<SecurityFinding> Analyze(IEnumerable<WindowsEvent> events);
}
