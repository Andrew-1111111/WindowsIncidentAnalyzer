using Microsoft.Extensions.Options;
using WindowsIncidentAnalyzer.Configuration;
using WindowsIncidentAnalyzer.Models;

namespace WindowsIncidentAnalyzer.Detectors;

public sealed class RdpActivityDetector(IOptions<DetectionRulesOptions> options) : DetectorBase
{
    private readonly RdpActivityOptions _options = options.Value.RdpActivity;

    public override string Name => "RdpActivity";

    public override string Description => "Highlights Remote Desktop (logon type 10) authentications.";

    public override DetectionSeverity Severity => DetectionSeverity.Low;

    public override bool IsEnabled => _options.Enabled;

    public override IReadOnlyList<int> RelevantEventIds => [4624];

    public override IEnumerable<SecurityFinding> Analyze(IEnumerable<WindowsEvent> events)
    {
        if (!IsEnabled)
        {
            yield break;
        }

        var groups = OfEventId(events, 4624)
            .Where(e => e.LogonType == 10)
            .Where(e => !IsMachineAccount(e))
            .GroupBy(e => (Account: AccountKey(e), Ip: IpKey(e)));

        foreach (var group in groups)
        {
            var list = group.OrderBy(e => e.TimeCreatedUtc).ToList();
            yield return CreateFinding(
                $"RDP logon: {list[0].TargetUserName ?? list[0].User}",
                $"{list.Count} RemoteInteractive (type 10) logon(s) from {group.Key.Ip}.",
                DetectionSeverity.Low,
                list[^1],
                list,
                $"account={group.Key.Account}; ip={group.Key.Ip}; workstation={list[0].WorkstationName}; count={list.Count}");
        }
    }
}
