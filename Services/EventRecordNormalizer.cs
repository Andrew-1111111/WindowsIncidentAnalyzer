using System.Diagnostics.Eventing.Reader;
using System.Globalization;
using System.Security;
using System.Security.Principal;
using System.Text;
using System.Xml;
using WindowsIncidentAnalyzer.Infrastructure;
using WindowsIncidentAnalyzer.Models;

namespace WindowsIncidentAnalyzer.Services;

public sealed class EventRecordNormalizer(EventXmlParser parser)
{
    public WindowsEvent Normalize(EventRecord record, bool preferNativeXml = false) =>
        TryNormalize(record, preferNativeXml) ?? BuildMinimalEvent(record);

    public WindowsEvent? TryNormalize(EventRecord record, bool preferNativeXml = false)
    {
        try
        {
            string? rawXml = null;
            if (preferNativeXml || ShouldTryNativeXml(record))
            {
                rawXml = TryExportXml(record);
                if (rawXml != null)
                {
                    var fromXml = parser.TryParse(rawXml);
                    if (fromXml != null)
                    {
                        EnrichFromRecord(fromXml, record, rawXml);
                        return fromXml;
                    }
                }
            }

            return FromRecord(record, rawXml);
        }
        catch
        {
            return null;
        }
    }

    internal static bool ShouldTryNativeXml(EventRecord record) =>
        ShouldTryNativeXml(record.LogName, record.ProviderName);

    internal static bool ShouldTryNativeXml(string? logName, string? providerName)
    {
        logName ??= string.Empty;
        providerName ??= string.Empty;

        if (logName.Equals(WindowsLogNames.Security, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        if (logName.Equals(WindowsLogNames.Sysmon, StringComparison.OrdinalIgnoreCase) ||
            providerName.Contains("Sysmon", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        if (logName.Equals(WindowsLogNames.PowerShell, StringComparison.OrdinalIgnoreCase) ||
            providerName.Contains("PowerShell", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        return false;
    }

    private static string? TryExportXml(EventRecord record)
    {
        try
        {
            return record.ToXml();
        }
        catch (XmlException)
        {
            return null;
        }
        catch (EventLogException)
        {
            return null;
        }
        catch (InvalidOperationException)
        {
            return null;
        }
    }

    private static void EnrichFromRecord(WindowsEvent evt, EventRecord record, string rawXml)
    {
        evt.RawXml = rawXml;
        evt.EventId = record.Id;
        evt.EventRecordId ??= record.RecordId;
        evt.TimeCreatedUtc = record.TimeCreated?.ToUniversalTime() ?? evt.TimeCreatedUtc;
        evt.Level ??= EventXmlParser.MapLevel(record.Level?.ToString(CultureInfo.InvariantCulture));
        evt.ProviderName ??= NullableText.Clean(record.ProviderName);
        evt.LogName ??= NullableText.Clean(record.LogName);
        evt.ComputerName ??= NullableText.Clean(record.MachineName);

        MergeProperties(evt, ExtractRecordProperties(record));
    }

    private static WindowsEvent FromRecord(EventRecord record, string? rawXml)
    {
        var properties = ExtractRecordProperties(record);
        var evt = new WindowsEvent
        {
            RawXml = rawXml ?? BuildSyntheticXml(record, properties),
            Properties = properties,
            EventId = record.Id,
            EventRecordId = record.RecordId,
            TimeCreatedUtc = record.TimeCreated?.ToUniversalTime()
                ?? DateTime.SpecifyKind(DateTime.MinValue, DateTimeKind.Utc),
            Level = EventXmlParser.MapLevel(record.Level?.ToString(CultureInfo.InvariantCulture)),
            ProviderName = NullableText.Clean(record.ProviderName),
            LogName = NullableText.Clean(record.LogName),
            ComputerName = NullableText.Clean(record.MachineName)
        };

        TryAddSecurityUserId(evt, record);
        EventFieldMapper.Apply(evt);
        return evt;
    }

    private static WindowsEvent BuildMinimalEvent(EventRecord record)
    {
        var evt = new WindowsEvent
        {
            RawXml = BuildSyntheticXml(record, properties: new Dictionary<string, string>()),
            EventId = record.Id,
            EventRecordId = record.RecordId,
            TimeCreatedUtc = record.TimeCreated?.ToUniversalTime()
                ?? DateTime.SpecifyKind(DateTime.MinValue, DateTimeKind.Utc),
            Level = EventXmlParser.MapLevel(record.Level?.ToString(CultureInfo.InvariantCulture)),
            ProviderName = NullableText.Clean(record.ProviderName),
            LogName = NullableText.Clean(record.LogName),
            ComputerName = NullableText.Clean(record.MachineName)
        };

        TryAddSecurityUserId(evt, record);
        EventFieldMapper.Apply(evt);
        return evt;
    }

    private static void TryAddSecurityUserId(WindowsEvent evt, EventRecord record)
    {
        try
        {
            if (record.UserId is SecurityIdentifier userId)
            {
                evt.Properties["SecurityUserId"] = userId.ToString();
            }
        }
        catch
        {
            // UserId is unavailable on some records.
        }
    }

    public static Dictionary<string, string> ExtractRecordProperties(EventRecord record)
    {
        var properties = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        // Do NOT call record.FormatDescription() here. For classic Application/System
        // providers with missing message DLLs it throws EventLogNotFoundException
        // ("file not found") on every event — flooding the VS debugger Output window
        // even when the exception is caught.

        try
        {
            var count = record.Properties.Count;
            for (var i = 0; i < count; i++)
            {
                try
                {
                    var value = FormatPropertyValue(record.Properties[i].Value);
                    if (string.IsNullOrEmpty(value))
                    {
                        continue;
                    }

                    properties[$"Data{i}"] = value;
                }
                catch
                {
                    // Skip unreadable property slots.
                }
            }
        }
        catch
        {
            // Properties are unavailable on some records.
        }

        return properties;
    }

    private static void MergeProperties(WindowsEvent evt, Dictionary<string, string> additional)
    {
        foreach (var (key, value) in additional)
        {
            if (!evt.Properties.ContainsKey(key))
            {
                evt.Properties[key] = value;
            }
        }
    }

    private static string? FormatPropertyValue(object? value) => value switch
    {
        null => null,
        string text => NullableText.Clean(text),
        byte[] bytes => Convert.ToHexString(bytes),
        IFormattable formattable => formattable.ToString(null, CultureInfo.InvariantCulture),
        _ => Convert.ToString(value, CultureInfo.InvariantCulture)
    };

    private static string BuildSyntheticXml(EventRecord record, IReadOnlyDictionary<string, string> properties)
    {
        var builder = new StringBuilder(512);
        builder.Append("<Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\"><System>");
        builder.Append("<Provider Name=\"").Append(XmlEscape(record.ProviderName)).Append("\" />");
        builder.Append("<EventID>").Append(record.Id).Append("</EventID>");
        if (record.RecordId is { } recordId)
        {
            builder.Append("<EventRecordID>").Append(recordId).Append("</EventRecordID>");
        }

        if (record.TimeCreated is { } created)
        {
            builder.Append("<TimeCreated SystemTime=\"")
                .Append(created.ToUniversalTime().ToString("o", CultureInfo.InvariantCulture))
                .Append("\" />");
        }

        if (!string.IsNullOrWhiteSpace(record.LogName))
        {
            builder.Append("<Channel>").Append(XmlEscape(record.LogName)).Append("</Channel>");
        }

        if (!string.IsNullOrWhiteSpace(record.MachineName))
        {
            builder.Append("<Computer>").Append(XmlEscape(record.MachineName)).Append("</Computer>");
        }

        builder.Append("</System><EventData>");
        foreach (var (name, value) in properties)
        {
            builder.Append("<Data Name=\"").Append(XmlEscape(name)).Append("\">")
                .Append(XmlEscape(value))
                .Append("</Data>");
        }

        builder.Append("</EventData></Event>");
        return builder.ToString();
    }

    private static string XmlEscape(string? value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return string.Empty;
        }

        return SecurityElement.Escape(value) ?? string.Empty;
    }
}
