using WindowsIncidentAnalyzer.Models;

namespace WindowsIncidentAnalyzer.Exporters;

/// <summary>
/// Applies an <see cref="EventQueryFilter"/> to export artifacts that are not loaded via event QueryAsync.
/// </summary>
internal static class ExportQueryFilter
{
    public static bool HasCriteria(EventQueryFilter? filter)
    {
        if (filter == null)
        {
            return false;
        }

        return filter.FromUtc.HasValue
               || filter.ToUtc.HasValue
               || filter.TimeRanges is { Count: > 0 }
               || filter.EventIds is { Count: > 0 }
               || !string.IsNullOrWhiteSpace(filter.User)
               || !string.IsNullOrWhiteSpace(filter.IpAddress)
               || !string.IsNullOrWhiteSpace(filter.ProcessName)
               || !string.IsNullOrWhiteSpace(filter.Keyword)
               || !string.IsNullOrWhiteSpace(filter.ComputerName)
               || !string.IsNullOrWhiteSpace(filter.LogName);
    }

    public static IReadOnlyList<SecurityFinding> FilterFindings(
        IReadOnlyList<SecurityFinding> findings,
        EventQueryFilter filter) =>
        findings.Where(f => MatchesFinding(f, filter)).ToList();

    public static IReadOnlyList<EventCorrelation> FilterCorrelations(
        IReadOnlyList<EventCorrelation> correlations,
        EventQueryFilter filter) =>
        correlations.Where(c => MatchesCorrelation(c, filter)).ToList();

    public static IReadOnlyList<IocMatch> FilterIocMatches(
        IReadOnlyList<IocMatch> matches,
        EventQueryFilter filter) =>
        matches.Where(m => MatchesIoc(m, filter)).ToList();

    public static IReadOnlyList<CveMatch> FilterCveMatches(
        IReadOnlyList<CveMatch> matches,
        EventQueryFilter filter) =>
        matches.Where(m => MatchesCve(m, filter)).ToList();

    private static bool MatchesFinding(SecurityFinding finding, EventQueryFilter filter)
    {
        var time = finding.Context.TimestampUtc ?? finding.TimeUtc;
        if (!MatchesTime(time, filter))
        {
            return false;
        }

        if (!MatchesUser(filter.User, finding.User, finding.Context.User, finding.Context.Domain))
        {
            return false;
        }

        if (!MatchesIp(filter.IpAddress, finding.SourceIpAddress, finding.Context.SourceIp, finding.Context.DestinationIp))
        {
            return false;
        }

        if (!MatchesProcess(
                filter.ProcessName,
                finding.ProcessName,
                finding.Context.ProcessName,
                finding.Context.Image,
                finding.Context.CommandLine,
                finding.Context.ParentImage,
                finding.Context.ParentCommandLine))
        {
            return false;
        }

        if (!MatchesHost(filter.ComputerName, finding.ComputerName, finding.Context.Host))
        {
            return false;
        }

        if (!MatchesLog(filter.LogName, finding.Context.Channel))
        {
            return false;
        }

        if (filter.EventIds is { Count: > 0 } ids &&
            (finding.Context.EventId is not int eventId || !ids.Contains(eventId)))
        {
            return false;
        }

        if (!MatchesKeyword(
                filter.Keyword,
                finding.Title,
                finding.Description,
                finding.Details,
                finding.Context.Reason,
                finding.Context.CommandLine,
                finding.Context.MatchedValues is { Count: > 0 } values
                    ? string.Join(' ', values)
                    : null))
        {
            return false;
        }

        return true;
    }

    private static bool MatchesCorrelation(EventCorrelation item, EventQueryFilter filter)
    {
        if (!MatchesTime(item.TimeUtc, filter))
        {
            return false;
        }

        if (!MatchesUser(filter.User, item.User))
        {
            return false;
        }

        if (!MatchesIp(filter.IpAddress, item.SourceIpAddress))
        {
            return false;
        }

        if (!MatchesHost(filter.ComputerName, item.ComputerName))
        {
            return false;
        }

        if (!MatchesKeyword(filter.Keyword, item.Title, item.Scenario, item.Interpretation, item.Details))
        {
            return false;
        }

        return true;
    }

    private static bool MatchesIoc(IocMatch match, EventQueryFilter filter)
    {
        if (!MatchesTime(match.TimestampUtc, filter))
        {
            return false;
        }

        if (!MatchesUser(filter.User, match.RelatedUser))
        {
            return false;
        }

        if (!string.IsNullOrWhiteSpace(filter.IpAddress) &&
            !Contains(match.IocValue, filter.IpAddress) &&
            !Contains(match.MatchedField, filter.IpAddress))
        {
            return false;
        }

        if (!MatchesProcess(filter.ProcessName, match.RelatedProcess))
        {
            return false;
        }

        if (!MatchesHost(filter.ComputerName, match.Host))
        {
            return false;
        }

        if (filter.EventIds is { Count: > 0 } ids && !ids.Contains(match.EventId))
        {
            return false;
        }

        if (!MatchesKeyword(filter.Keyword, match.IocValue, match.MatchedField, match.RelatedProcess, match.RelatedUser))
        {
            return false;
        }

        return true;
    }

    private static bool MatchesCve(CveMatch match, EventQueryFilter filter)
    {
        if (!MatchesTime(match.TimestampUtc, filter))
        {
            return false;
        }

        if (!MatchesUser(filter.User, match.RelatedUser))
        {
            return false;
        }

        if (!MatchesProcess(filter.ProcessName, match.RelatedProcess))
        {
            return false;
        }

        if (!MatchesHost(filter.ComputerName, match.Host))
        {
            return false;
        }

        if (filter.EventIds is { Count: > 0 } ids && !ids.Contains(match.EventId))
        {
            return false;
        }

        if (!MatchesKeyword(
                filter.Keyword,
                match.CveId,
                match.VulnerabilityName,
                match.ShortDescription,
                match.Product,
                match.VendorProject,
                match.MatchedField))
        {
            return false;
        }

        return true;
    }

    private static bool MatchesTime(DateTime timeUtc, EventQueryFilter filter)
    {
        if (filter.TimeRanges is { Count: > 0 } ranges)
        {
            return ranges.Any(r => timeUtc >= r.FromUtc && timeUtc <= r.ToUtc);
        }

        if (filter.FromUtc is DateTime from && timeUtc < from)
        {
            return false;
        }

        if (filter.ToUtc is DateTime to && timeUtc > to)
        {
            return false;
        }

        return true;
    }

    private static bool MatchesUser(string? needle, params string?[] values) => MatchesAny(needle, values);

    private static bool MatchesIp(string? needle, params string?[] values) => MatchesAny(needle, values);

    private static bool MatchesProcess(string? needle, params string?[] values) => MatchesAny(needle, values);

    private static bool MatchesHost(string? needle, params string?[] values) => MatchesAny(needle, values);

    private static bool MatchesLog(string? needle, params string?[] values) => MatchesAny(needle, values);

    private static bool MatchesKeyword(string? needle, params string?[] values) => MatchesAny(needle, values);

    private static bool MatchesAny(string? needle, params string?[] values)
    {
        if (string.IsNullOrWhiteSpace(needle))
        {
            return true;
        }

        return values.Any(v => Contains(v, needle));
    }

    private static bool Contains(string? haystack, string needle) =>
        !string.IsNullOrWhiteSpace(haystack) &&
        haystack.Contains(needle.Trim(), StringComparison.OrdinalIgnoreCase);
}
