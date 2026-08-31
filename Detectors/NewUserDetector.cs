using Microsoft.Extensions.Options;
using WindowsIncidentAnalyzer.Configuration;
using WindowsIncidentAnalyzer.Infrastructure;
using WindowsIncidentAnalyzer.Models;

namespace WindowsIncidentAnalyzer.Detectors;

public sealed class NewUserDetector(IOptions<DetectionRulesOptions> options) : DetectorBase
{
    private readonly NewUserOptions _options = options.Value.NewUser;
    private readonly PrivilegeChangeOptions _privilege = options.Value.PrivilegeChange;

    public override string Name => "NewUser";

    public override string Description => "Detects user account creation (4720) and nearby privileged group assignments.";

    public override DetectionSeverity Severity => DetectionSeverity.Medium;

    public override bool IsEnabled => _options.Enabled;

    public override IReadOnlyList<int> RelevantEventIds => [4720, 4728, 4732, 4756];

    public override IEnumerable<SecurityFinding> Analyze(IEnumerable<WindowsEvent> events)
    {
        if (!IsEnabled)
        {
            yield break;
        }

        var materialized = events.ToList();
        var created = OfEventId(materialized, 4720).ToList();
        var groupAdds = OfEventId(materialized, 4728, 4732, 4756).ToList();
        var window = TimeSpan.FromMinutes(Math.Max(1, _options.PrivilegeWindowMinutes));

        foreach (var evt in created)
        {
            var newUser = evt.TargetUserName ?? evt.GetProperty("TargetUserName");
            var priv = groupAdds
                .Where(g => MemberMatches(g, newUser))
                .Where(g => g.TimeCreatedUtc >= evt.TimeCreatedUtc && g.TimeCreatedUtc <= evt.TimeCreatedUtc + window)
                .Where(g => WindowsLocale.IsPrivilegedGroup(
                    g.GetProperty("TargetUserName") ?? g.TargetUserName,
                    FirstNonEmpty(g.GetProperty("TargetSid"), g.GetProperty("TargetUserSid")),
                    _privilege.PrivilegedGroups))
                .ToList();

            var severity = priv.Count > 0 ? DetectionSeverity.High : DetectionSeverity.Medium;
            var title = priv.Count > 0
                ? "New user created and added to a privileged group"
                : "New user account created";

            yield return CreateFinding(
                title,
                $"Account '{newUser}' was created by '{evt.User}' on {evt.ComputerName}.",
                severity,
                evt,
                priv.Prepend(evt),
                $"creator={evt.User}; domain={evt.TargetDomainName ?? evt.Domain}; newUser={newUser}; privilegedGroupEvents={priv.Count}");
        }
    }

    private static bool MemberMatches(WindowsEvent groupEvent, string? newUser) =>
        ContainsIgnoreCase(groupEvent.GetProperty("MemberName"), newUser)
        || ContainsIgnoreCase(groupEvent.RawXml, newUser)
        || string.Equals(groupEvent.TargetUserName, newUser, StringComparison.OrdinalIgnoreCase);

    private static string? FirstNonEmpty(params string?[] values) =>
        values.FirstOrDefault(v => !string.IsNullOrWhiteSpace(v));

    private static bool ContainsIgnoreCase(string? haystack, string? needle) =>
        !string.IsNullOrEmpty(haystack) && !string.IsNullOrEmpty(needle) &&
        haystack.Contains(needle, StringComparison.OrdinalIgnoreCase);
}
