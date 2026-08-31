using System.Globalization;
using System.Text.RegularExpressions;
using WindowsIncidentAnalyzer.Models;

namespace WindowsIncidentAnalyzer.Infrastructure;

public static partial class EventIdentity
{
    public static string BuildKey(WindowsEvent evt) =>
        BuildKey(
            evt.ComputerName,
            evt.LogName,
            evt.ProviderName,
            evt.EventId,
            evt.TimeCreatedUtc,
            evt.EventRecordId);

    public static string BuildKey(
        string? computerName,
        string? logName,
        string? providerName,
        int eventId,
        DateTime timeCreatedUtc,
        long? eventRecordId)
    {
        var identity = eventRecordId is { } recordId
            ? "record:" + recordId.ToString(CultureInfo.InvariantCulture)
            : "time:" + DateTimeParser.Iso(timeCreatedUtc);
        return string.Join(
            '|',
            Normalize(computerName),
            Normalize(logName),
            Normalize(providerName),
            eventId.ToString(CultureInfo.InvariantCulture),
            identity);
    }

    public static long? ExtractRecordId(string? rawXml)
    {
        if (string.IsNullOrWhiteSpace(rawXml))
        {
            return null;
        }

        var match = EventRecordIdRegex().Match(rawXml);
        return match.Success &&
               long.TryParse(match.Groups[1].Value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var id)
            ? id
            : null;
    }

    private static string Normalize(string? value) =>
        value?.Trim().ToLowerInvariant() ?? string.Empty;

    [GeneratedRegex(
        @"<EventRecordID(?:\s[^>]*)?>(\d+)</EventRecordID>",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex EventRecordIdRegex();
}
