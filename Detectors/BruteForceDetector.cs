using Microsoft.Extensions.Options;
using WindowsIncidentAnalyzer.Configuration;
using WindowsIncidentAnalyzer.Models;

namespace WindowsIncidentAnalyzer.Detectors;

public sealed class BruteForceDetector(IOptions<DetectionRulesOptions> options) : DetectorBase
{
    private readonly BruteForceOptions _options = options.Value.BruteForce;

    public override string Name => "BruteForce";

    public override string Description =>
        "Detects clustered authentication failures, successful brute force, and password spraying across multiple accounts.";

    public override DetectionSeverity Severity => DetectionSeverity.High;

    public override bool IsEnabled => _options.Enabled;

    public override IReadOnlyList<int> RelevantEventIds => [4624, 4625, 4771, 4776];

    public override IEnumerable<SecurityFinding> Analyze(IEnumerable<WindowsEvent> events)
    {
        if (!IsEnabled)
        {
            yield break;
        }

        var materialized = events.ToList();
        var failures = materialized
            .Where(IsAuthenticationFailure)
            .Where(e => !string.IsNullOrEmpty(e.TargetUserName ?? e.User))
            .OrderBy(e => e.TimeCreatedUtc)
            .ToList();

        var successes = OfEventId(materialized, 4624).ToList();
        var window = TimeSpan.FromMinutes(Math.Max(1, _options.TimeWindowMinutes));
        var threshold = Math.Max(2, _options.FailedAttemptsThreshold);
        var emitted = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        var grouped = failures.GroupBy(e => (Account: AccountKey(e), Ip: IpKey(e)));

        foreach (var group in grouped)
        {
            var list = group.ToList();
            for (var i = 0; i < list.Count; i++)
            {
                var start = list[i].TimeCreatedUtc;
                var cluster = new List<WindowsEvent> { list[i] };
                for (var j = i + 1; j < list.Count; j++)
                {
                    if (list[j].TimeCreatedUtc - start <= window)
                    {
                        cluster.Add(list[j]);
                    }
                    else
                    {
                        break;
                    }
                }

                if (cluster.Count < threshold)
                {
                    continue;
                }

                var key = $"{group.Key.Account}|{group.Key.Ip}|{cluster[0].TimeCreatedUtc:o}";
                if (!emitted.Add(key))
                {
                    continue;
                }

                var lastFail = cluster[^1];
                var success = successes
                    .Where(s => string.Equals(AccountKey(s), group.Key.Account, StringComparison.OrdinalIgnoreCase)
                                && string.Equals(IpKey(s), group.Key.Ip, StringComparison.OrdinalIgnoreCase)
                                && s.TimeCreatedUtc >= lastFail.TimeCreatedUtc
                                && s.TimeCreatedUtc <= lastFail.TimeCreatedUtc + window)
                    .OrderBy(s => s.TimeCreatedUtc)
                    .FirstOrDefault();

                if (success != null)
                {
                    var related = cluster.Concat([success]).ToList();
                    yield return CreateFinding(
                        "Possible successful brute force authentication",
                        $"{cluster.Count} failed logons for the same user and source IP were followed by a successful logon (4624) within {window.TotalMinutes:0} minutes.",
                        DetectionSeverity.High,
                        success,
                        related,
                        $"account={group.Key.Account}; ip={group.Key.Ip}; failures={cluster.Count}; success={success.TimeCreatedUtc:o}");
                }
                else
                {
                    yield return CreateFinding(
                        "Possible brute force authentication",
                        $"{cluster.Count} failed logons for the same user and source IP occurred within {window.TotalMinutes:0} minutes.",
                        DetectionSeverity.Medium,
                        lastFail,
                        cluster,
                        $"account={group.Key.Account}; ip={group.Key.Ip}; failures={cluster.Count}");
                }

                i += cluster.Count - 1;
            }
        }

        var sprayThreshold = Math.Max(3, _options.PasswordSprayAccountThreshold);
        foreach (var sourceGroup in failures
                     .Where(e => !string.IsNullOrWhiteSpace(IpKey(e)) && IpKey(e) != "-")
                     .GroupBy(IpKey, StringComparer.OrdinalIgnoreCase))
        {
            var sourceEvents = sourceGroup.OrderBy(e => e.TimeCreatedUtc).ToList();
            for (var i = 0; i < sourceEvents.Count; i++)
            {
                var cluster = sourceEvents
                    .Skip(i)
                    .TakeWhile(e => e.TimeCreatedUtc - sourceEvents[i].TimeCreatedUtc <= window)
                    .ToList();
                var accounts = cluster
                    .Select(AccountKey)
                    .Where(account => !string.IsNullOrWhiteSpace(account.Trim('\\')))
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .ToList();
                if (accounts.Count < sprayThreshold)
                {
                    continue;
                }

                yield return CreateFinding(
                    "Possible password spraying",
                    $"{cluster.Count} authentication failures targeted {accounts.Count} distinct accounts from the same source within {window.TotalMinutes:0} minutes.",
                    DetectionSeverity.High,
                    cluster[^1],
                    cluster,
                    $"ip={sourceGroup.Key}; attempts={cluster.Count}; distinctAccounts={accounts.Count}; accounts={string.Join(",", accounts.Take(20))}");
                i += cluster.Count - 1;
            }
        }
    }

    private static bool IsAuthenticationFailure(WindowsEvent evt)
    {
        if (evt.EventId is 4625 or 4771)
        {
            return true;
        }

        if (evt.EventId != 4776)
        {
            return false;
        }

        var status = evt.GetProperty("Status");
        return !string.IsNullOrWhiteSpace(status) &&
               status is not "0" &&
               !status.Equals("0x0", StringComparison.OrdinalIgnoreCase) &&
               !status.Equals("0x00000000", StringComparison.OrdinalIgnoreCase);
    }
}
