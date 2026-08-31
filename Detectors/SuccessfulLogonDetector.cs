using Microsoft.Extensions.Options;
using WindowsIncidentAnalyzer.Configuration;
using WindowsIncidentAnalyzer.Models;

namespace WindowsIncidentAnalyzer.Detectors;

public sealed class SuccessfulLogonDetector(IOptions<DetectionRulesOptions> options) : DetectorBase
{
    private readonly SuccessfulLogonOptions _options = options.Value.SuccessfulLogon;

    public override string Name => "SuccessfulLogon";

    public override string Description => "Summarizes remote and explicit-credential successful authentications.";

    public override DetectionSeverity Severity => DetectionSeverity.Info;

    public override bool IsEnabled => _options.Enabled;

    public override IReadOnlyList<int> RelevantEventIds => [4624, 4648];

    public override IEnumerable<SecurityFinding> Analyze(IEnumerable<WindowsEvent> events)
    {
        if (!IsEnabled)
        {
            yield break;
        }

        var remote = OfEventId(events, 4624)
            .Where(e => e.LogonType is 3 or 8 or 9 or 10 or 11)
            .Where(e => !IsMachineAccount(e))
            .GroupBy(e => (Account: AccountKey(e), Type: e.LogonType, Ip: IpKey(e)));

        foreach (var group in remote)
        {
            var list = group.OrderBy(e => e.TimeCreatedUtc).ToList();
            var logonName = group.Key.Type switch
            {
                3 => "Network",
                8 => "NetworkCleartext",
                9 => "NewCredentials",
                10 => "RemoteInteractive (RDP)",
                11 => "CachedRemoteInteractive",
                _ => group.Key.Type?.ToString() ?? "unknown"
            };

            yield return CreateFinding(
                $"Successful {logonName} logon: {list[0].TargetUserName ?? list[0].User}",
                $"Account authenticated successfully with logon type {group.Key.Type} from {group.Key.Ip}.",
                group.Key.Type is 8 or 10 ? DetectionSeverity.Low : DetectionSeverity.Info,
                list[^1],
                list,
                $"count={list.Count}; logonType={group.Key.Type}; ip={group.Key.Ip}");
        }

        foreach (var evt in OfEventId(events, 4648).Where(e => !IsMachineAccount(e)))
        {
            yield return CreateFinding(
                "Logon with explicit credentials",
                "Event 4648 records a logon that supplied alternate credentials (runas / mapped drive / lateral movement pattern).",
                DetectionSeverity.Low,
                evt,
                details: $"target={evt.TargetUserName}; process={evt.ProcessName}; ip={evt.SourceIpAddress}");
        }
    }
}
