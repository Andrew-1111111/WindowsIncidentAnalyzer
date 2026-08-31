using Microsoft.Extensions.Options;
using WindowsIncidentAnalyzer.Configuration;
using WindowsIncidentAnalyzer.Models;

namespace WindowsIncidentAnalyzer.Detectors;

public sealed class KerberosAndDirectoryAttackDetector(IOptions<DetectionRulesOptions> options) : DetectorBase
{
    private static readonly string[] ReplicationGuids =
    [
        "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2",
        "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2",
        "89e95b76-444d-4c62-991a-0facbeda640c"
    ];

    private readonly KnownThreatSignaturesOptions _options = options.Value.KnownThreatSignatures;
    private readonly BruteForceOptions _bruteForce = options.Value.BruteForce;

    public override string Name => "KerberosAndDirectoryAttack";
    public override string Description => "Detects DCSync rights use, Kerberoasting/AS-REP roasting indicators, and Kerberos pre-authentication bursts.";
    public override DetectionSeverity Severity => DetectionSeverity.High;
    public override bool IsEnabled => _options.Enabled;
    public override IReadOnlyList<int> RelevantEventIds => [4662, 4740, 4768, 4769, 4771];

    public override IEnumerable<SecurityFinding> Analyze(IEnumerable<WindowsEvent> events)
    {
        if (!IsEnabled)
        {
            yield break;
        }

        var list = events.OrderBy(e => e.TimeCreatedUtc).ToList();

        foreach (var evt in list.Where(e => e.EventId == 4662 && ContainsAny(e, ReplicationGuids)))
        {
            yield return CreateFinding(
                "Directory replication rights used (possible DCSync)",
                "Event 4662 contains directory replication extended-right GUIDs. Confirm that the requesting identity is an authorized domain controller or replication service.",
                DetectionSeverity.Critical,
                evt,
                details: $"signature=AD-001; subject={evt.User}; object={evt.GetProperty("ObjectName")}; properties={evt.GetProperty("Properties")}");
        }

        foreach (var evt in list.Where(IsAsRepRoastIndicator))
        {
            yield return CreateFinding(
                "AS-REP roasting indicator",
                "A Kerberos TGT request used no pre-authentication with RC4 encryption. Validate whether the account intentionally has pre-authentication disabled.",
                DetectionSeverity.High,
                evt,
                details: $"signature=AD-002; account={Account(evt)}; ip={Source(evt)}; encryption={Property(evt, "TicketEncryptionType")}");
        }

        var window = TimeSpan.FromMinutes(Math.Max(1, _bruteForce.TimeWindowMinutes));
        var threshold = Math.Max(3, _bruteForce.FailedAttemptsThreshold);
        foreach (var group in list.Where(e => e.EventId == 4771).GroupBy(e => $"{Account(e)}|{Source(e)}", StringComparer.OrdinalIgnoreCase))
        {
            var ordered = group.OrderBy(e => e.TimeCreatedUtc).ToList();
            var cluster = LargestCluster(ordered, window);
            if (cluster.Count < threshold)
            {
                continue;
            }

            yield return CreateFinding(
                "Kerberos pre-authentication failure burst",
                $"{cluster.Count} Kerberos pre-authentication failures occurred for the same account and source within {window.TotalMinutes:N0} minutes.",
                DetectionSeverity.High,
                cluster[^1],
                cluster,
                $"signature=AD-003; account={Account(cluster[0])}; ip={Source(cluster[0])}; count={cluster.Count}; status={Property(cluster[0], "Status", "FailureCode")}");
        }

        foreach (var group in list.Where(IsKerberoastTicket).GroupBy(e => $"{Account(e)}|{Source(e)}", StringComparer.OrdinalIgnoreCase))
        {
            var ordered = group.OrderBy(e => e.TimeCreatedUtc).ToList();
            var cluster = LargestCluster(ordered, window);
            var distinctServices = cluster
                .Select(e => Property(e, "ServiceName"))
                .Where(value => !string.IsNullOrWhiteSpace(value))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Count();
            if (cluster.Count < 5 || distinctServices < 3)
            {
                continue;
            }

            yield return CreateFinding(
                "Kerberoasting ticket-request burst",
                $"{cluster.Count} RC4 service tickets for {distinctServices} distinct services were requested in a short interval.",
                DetectionSeverity.High,
                cluster[^1],
                cluster,
                $"signature=AD-004; account={Account(cluster[0])}; ip={Source(cluster[0])}; tickets={cluster.Count}; services={distinctServices}");
        }

        foreach (var evt in list.Where(e => e.EventId == 4740))
        {
            yield return CreateFinding(
                "User account locked out",
                "A user account was locked out. Correlate with 4625/4771 failures and the caller computer.",
                DetectionSeverity.Medium,
                evt,
                details: $"signature=AD-005; account={Account(evt)}; caller={Property(evt, "CallerComputerName", "WorkstationName")}");
        }
    }

    private static bool IsAsRepRoastIndicator(WindowsEvent evt) =>
        evt.EventId == 4768 &&
        Property(evt, "PreAuthType", "PreAuthenticationType") is "0" &&
        IsRc4(Property(evt, "TicketEncryptionType"));

    private static bool IsKerberoastTicket(WindowsEvent evt)
    {
        if (evt.EventId != 4769 || !IsRc4(Property(evt, "TicketEncryptionType")))
        {
            return false;
        }

        var service = Property(evt, "ServiceName");
        return !string.IsNullOrWhiteSpace(service) &&
               !service.StartsWith("krbtgt", StringComparison.OrdinalIgnoreCase) &&
               !service.EndsWith('$');
    }

    private static bool IsRc4(string value) =>
        value.Equals("0x17", StringComparison.OrdinalIgnoreCase) ||
        value.Equals("23", StringComparison.OrdinalIgnoreCase);

    private static bool ContainsAny(WindowsEvent evt, IEnumerable<string> tokens)
    {
        var blob = evt.RawXml + "\n" + string.Join('\n', evt.Properties.Values);
        return tokens.Any(token => blob.Contains(token, StringComparison.OrdinalIgnoreCase));
    }

    private static string Account(WindowsEvent evt) =>
        Property(evt, "TargetUserName", "TargetName", "AccountName") is { Length: > 0 } account
            ? account
            : evt.TargetUserName ?? evt.User ?? string.Empty;

    private static string Source(WindowsEvent evt) =>
        Property(evt, "IpAddress", "ClientAddress") is { Length: > 0 } source
            ? source
            : evt.SourceIpAddress ?? string.Empty;

    private static string Property(WindowsEvent evt, params string[] names)
    {
        foreach (var name in names)
        {
            var value = evt.GetProperty(name);
            if (!string.IsNullOrWhiteSpace(value))
            {
                return value;
            }
        }

        return string.Empty;
    }

    private static List<WindowsEvent> LargestCluster(IReadOnlyList<WindowsEvent> events, TimeSpan window)
    {
        var best = new List<WindowsEvent>();
        for (var start = 0; start < events.Count; start++)
        {
            var cluster = events
                .Skip(start)
                .TakeWhile(e => e.TimeCreatedUtc - events[start].TimeCreatedUtc <= window)
                .ToList();
            if (cluster.Count > best.Count)
            {
                best = cluster;
            }
        }

        return best;
    }
}
