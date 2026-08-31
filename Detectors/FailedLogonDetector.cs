using WindowsIncidentAnalyzer.Configuration;
using WindowsIncidentAnalyzer.Models;
using Microsoft.Extensions.Options;

namespace WindowsIncidentAnalyzer.Detectors;

public sealed class FailedLogonDetector(IOptions<DetectionRulesOptions> options) : DetectorBase
{
    private readonly FailedLogonOptions _options = options.Value.FailedLogon;

    public override string Name => "FailedLogon";

    public override string Description => "Clusters failed authentication events (4625) by user and source IP.";

    public override DetectionSeverity Severity => DetectionSeverity.Low;

    public override bool IsEnabled => _options.Enabled;

    public override IReadOnlyList<int> RelevantEventIds => [4625];

    public override IEnumerable<SecurityFinding> Analyze(IEnumerable<WindowsEvent> events)
    {
        if (!IsEnabled)
        {
            yield break;
        }

        var groups = OfEventId(events, 4625)
            .Where(e => !string.IsNullOrEmpty(e.TargetUserName ?? e.User))
            .GroupBy(e => (Account: AccountKey(e), Ip: IpKey(e)));

        foreach (var group in groups)
        {
            var list = group.OrderBy(e => e.TimeCreatedUtc).ToList();
            if (list.Count < Math.Max(1, _options.ClusterThreshold))
            {
                continue;
            }

            var first = list[0];
            yield return CreateFinding(
                $"Failed logons for {first.TargetUserName ?? first.User}",
                $"{list.Count} failed logon events (4625) for the same account and source IP.",
                DetectionSeverity.Low,
                list[^1],
                list,
                $"account={group.Key.Account}; ip={group.Key.Ip}; count={list.Count}; first={first.TimeCreatedUtc:o}; last={list[^1].TimeCreatedUtc:o}");
        }
    }
}
