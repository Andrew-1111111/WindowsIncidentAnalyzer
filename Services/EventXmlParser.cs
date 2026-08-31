using System.Globalization;
using System.Xml.Linq;
using WindowsIncidentAnalyzer.Infrastructure;
using WindowsIncidentAnalyzer.Models;

namespace WindowsIncidentAnalyzer.Services;

public sealed class EventXmlParser
{
    public static readonly XNamespace EventNs = "http://schemas.microsoft.com/win/2004/08/events/event";

    public WindowsEvent Parse(string xml)
    {
        if (string.IsNullOrWhiteSpace(xml))
        {
            throw new ArgumentException("Event XML is empty.", nameof(xml));
        }

        XDocument document;
        try
        {
            document = XDocument.Parse(xml, LoadOptions.None);
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException("Event XML could not be parsed.", ex);
        }

        var root = document.Root ?? throw new InvalidOperationException("Event XML has no root element.");
        var system = root.Element(EventNs + "System");
        var eventData = root.Element(EventNs + "EventData") ?? root.Element(EventNs + "UserData");

        var properties = ExtractProperties(eventData);
        var eventIdElement = system?.Element(EventNs + "EventID");
        var qualifiers = eventIdElement?.Attribute("Qualifiers")?.Value;

        var evt = new WindowsEvent
        {
            RawXml = xml,
            Properties = properties,
            LogName = NullableText.Clean(system?.Element(EventNs + "Channel")?.Value),
            ProviderName = NullableText.Clean(system?.Element(EventNs + "Provider")?.Attribute("Name")?.Value),
            EventId = ParseInt(eventIdElement?.Value) ?? 0,
            EventRecordId = ParseLong(system?.Element(EventNs + "EventRecordID")?.Value),
            TimeCreatedUtc = ParseTimestamp(system?.Element(EventNs + "TimeCreated")?.Attribute("SystemTime")?.Value),
            Level = MapLevel(system?.Element(EventNs + "Level")?.Value),
            ComputerName = NullableText.Clean(system?.Element(EventNs + "Computer")?.Value)
        };

        var userId = NullableText.Clean(system?.Element(EventNs + "Security")?.Attribute("UserID")?.Value);
        if (userId != null)
        {
            evt.Properties["SecurityUserId"] = userId;
        }

        if (!string.IsNullOrEmpty(qualifiers))
        {
            evt.Properties["EventIdQualifiers"] = qualifiers;
        }

        EventFieldMapper.Apply(evt);
        return evt;
    }

    public static Dictionary<string, string> ExtractProperties(XElement? eventData)
    {
        var properties = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (eventData == null)
        {
            return properties;
        }

        var unnamedIndex = 0;
        foreach (var data in eventData.Descendants().Where(e => e.Name.LocalName == "Data" || e.Name.LocalName.Length > 0))
        {
            if (data.Name.LocalName is "EventData" or "UserData")
            {
                continue;
            }

            if (data.Name.LocalName != "Data" && data.HasElements)
            {
                continue;
            }

            var name = data.Attribute("Name")?.Value;
            if (string.IsNullOrWhiteSpace(name))
            {
                if (data.Name.LocalName != "Data")
                {
                    name = data.Name.LocalName;
                }
                else
                {
                    name = $"Data{unnamedIndex++}";
                }
            }

            var value = data.Value;
            if (string.IsNullOrEmpty(value))
            {
                continue;
            }

            properties[name] = value;
        }

        return properties;
    }

    public static int? ParseInt(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        var token = value.Trim();
        if (token.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
        {
            if (int.TryParse(token[2..], NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var hex))
            {
                return hex;
            }
        }

        if (int.TryParse(token, NumberStyles.Integer, CultureInfo.InvariantCulture, out var number))
        {
            return number;
        }

        return null;
    }

    public static long? ParseLong(string? value) =>
        long.TryParse(value?.Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture, out var number)
            ? number
            : null;

    public static DateTime ParseTimestamp(string? value)
    {
        var parsed = DateTimeParser.Parse(value);
        return parsed ?? DateTime.SpecifyKind(DateTime.MinValue, DateTimeKind.Utc);
    }

    public static string MapLevel(string? level)
    {
        return level?.Trim() switch
        {
            "0" => "LogAlways",
            "1" => "Critical",
            "2" => "Error",
            "3" => "Warning",
            "4" => "Information",
            "5" => "Verbose",
            null or "" => "Unknown",
            _ => level
        };
    }
}
