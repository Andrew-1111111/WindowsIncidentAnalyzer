using System.Globalization;
using WindowsIncidentAnalyzer.Models;

namespace WindowsIncidentAnalyzer.Infrastructure;

public static class DateRangeParser
{
    private const string DateFormat = "yyyy-MM-dd";

    public static IReadOnlyList<TimeRange> Parse(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return [];
        }

        var ranges = new List<TimeRange>();
        foreach (var token in value.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            ranges.Add(ParseToken(token));
        }

        if (ranges.Count == 0)
        {
            throw new ArgumentException(
                $"Invalid --date value '{value}'. Use yyyy-MM-dd, comma-separated dates, or a range yyyy-MM-dd..yyyy-MM-dd.");
        }

        return Merge(ranges);
    }

    public static string DescribeLocal(IReadOnlyList<TimeRange> ranges)
    {
        if (ranges.Count == 0)
        {
            return string.Empty;
        }

        return string.Join(", ", ranges.Select(DescribeOne));
    }

    private static string DescribeOne(TimeRange range)
    {
        var start = range.FromUtc.ToLocalTime().Date;
        var end = range.ToUtc.ToLocalTime().Date;
        return start == end
            ? start.ToString(DateFormat, CultureInfo.InvariantCulture)
            : $"{start.ToString(DateFormat, CultureInfo.InvariantCulture)}..{end.ToString(DateFormat, CultureInfo.InvariantCulture)}";
    }

    private static TimeRange ParseToken(string token)
    {
        foreach (var separator in new[] { "..", "/" })
        {
            var parts = token.Split(separator, 2, StringSplitOptions.TrimEntries);
            if (parts.Length != 2)
            {
                continue;
            }

            var start = ParseLocalDate(parts[0], token);
            var end = ParseLocalDate(parts[1], token);
            return LocalSpan(start, end);
        }

        var day = ParseLocalDate(token, token);
        return LocalDay(day);
    }

    private static DateTime ParseLocalDate(string text, string original)
    {
        if (DateTime.TryParseExact(
                text,
                DateFormat,
                CultureInfo.InvariantCulture,
                DateTimeStyles.None,
                out var date))
        {
            return date.Date;
        }

        throw new ArgumentException(
            $"Invalid --date value '{original}'. Use yyyy-MM-dd, comma-separated dates, or a range yyyy-MM-dd..yyyy-MM-dd.");
    }

    private static TimeRange LocalDay(DateTime localDate)
    {
        var start = DateTime.SpecifyKind(localDate.Date, DateTimeKind.Local);
        var end = start.AddDays(1).AddTicks(-1);
        return new TimeRange(start.ToUniversalTime(), end.ToUniversalTime());
    }

    private static TimeRange LocalSpan(DateTime localStart, DateTime localEnd)
    {
        if (localEnd < localStart)
        {
            (localStart, localEnd) = (localEnd, localStart);
        }

        var start = DateTime.SpecifyKind(localStart.Date, DateTimeKind.Local);
        var end = DateTime.SpecifyKind(localEnd.Date, DateTimeKind.Local).AddDays(1).AddTicks(-1);
        return new TimeRange(start.ToUniversalTime(), end.ToUniversalTime());
    }

    internal static IReadOnlyList<TimeRange> Merge(IReadOnlyList<TimeRange> ranges)
    {
        if (ranges.Count <= 1)
        {
            return ranges;
        }

        var ordered = ranges.OrderBy(r => r.FromUtc).ToList();
        var merged = new List<TimeRange> { ordered[0] };
        for (var i = 1; i < ordered.Count; i++)
        {
            var current = ordered[i];
            var last = merged[^1];
            if (current.FromUtc <= last.ToUtc.AddMinutes(1))
            {
                merged[^1] = new TimeRange(last.FromUtc, current.ToUtc > last.ToUtc ? current.ToUtc : last.ToUtc);
            }
            else
            {
                merged.Add(current);
            }
        }

        return merged;
    }
}
