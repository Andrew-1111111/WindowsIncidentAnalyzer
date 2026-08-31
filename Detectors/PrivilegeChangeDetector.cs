using Microsoft.Extensions.Options;
using WindowsIncidentAnalyzer.Configuration;
using WindowsIncidentAnalyzer.Infrastructure;
using WindowsIncidentAnalyzer.Models;

namespace WindowsIncidentAnalyzer.Detectors;

public sealed class PrivilegeChangeDetector(IOptions<DetectionRulesOptions> options) : DetectorBase
{
    private readonly PrivilegeChangeOptions _options = options.Value.PrivilegeChange;

    public override string Name => "PrivilegeChange";

    public override string Description => "Flags privileged group membership changes, special privilege logons, and new services.";

    public override DetectionSeverity Severity => DetectionSeverity.High;

    public override bool IsEnabled => _options.Enabled;

    public override IReadOnlyList<int> RelevantEventIds => [4672, 4728, 4732, 4756];

    public override IEnumerable<SecurityFinding> Analyze(IEnumerable<WindowsEvent> events)
    {
        if (!IsEnabled)
        {
            yield break;
        }

        foreach (var evt in OfEventId(events, 4728, 4732, 4756))
        {
            var group = evt.GetProperty("TargetUserName");
            if (string.IsNullOrEmpty(group))
            {
                group = evt.TargetUserName ?? evt.GetProperty("GroupName");
            }

            var member = evt.GetProperty("MemberName");
            if (string.IsNullOrEmpty(member))
            {
                member = evt.GetProperty("MemberSid");
            }

            var groupSid = evt.GetProperty("TargetSid");
            if (string.IsNullOrEmpty(groupSid))
            {
                groupSid = evt.GetProperty("TargetUserSid");
            }

            var privileged = WindowsLocale.IsPrivilegedGroup(group, groupSid, _options.PrivilegedGroups)
                             || (!string.IsNullOrEmpty(evt.RawXml) && WindowsLocale.IsPrivilegedGroup(evt.RawXml, null, _options.PrivilegedGroups));

            if (!privileged)
            {
                continue;
            }

            yield return CreateFinding(
                "User added to a privileged group",
                $"A membership change assigned '{member}' to '{group}'.",
                DetectionSeverity.High,
                evt,
                details: $"actor={evt.User}; member={member}; group={group}; eventId={evt.EventId}");
        }

        foreach (var evt in OfEventId(events, 4672).Where(e => !IsMachineAccount(e)))
        {
            yield return CreateFinding(
                "Special privileges assigned to new logon",
                $"Event 4672 indicates a privileged logon for '{evt.User}'.",
                DetectionSeverity.Low,
                evt,
                details: evt.GetProperty("PrivilegeList"));
        }

    }
}
