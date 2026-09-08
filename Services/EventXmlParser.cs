using System.Globalization;
using System.Xml;
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

        return TryParseCore(xml)
            ?? throw new InvalidOperationException("Event XML could not be parsed.");
    }

    public WindowsEvent? TryParse(string xml) =>
        string.IsNullOrWhiteSpace(xml) ? null : TryParseCore(xml);

    private WindowsEvent? TryParseCore(string xml)
    {
        if (!TryLoadDocument(xml, out var document, out var root))
        {
            return null;
        }

        try
        {
            var system = FindChild(root, "System");
            var properties = ExtractProperties(FindChild(root, "EventData"));
            foreach (var (key, value) in ExtractProperties(FindChild(root, "UserData")))
            {
                properties.TryAdd(key, value);
            }

            var eventIdElement = system?.Elements().FirstOrDefault(e => e.Name.LocalName == "EventID");
            var qualifiers = eventIdElement?.Attribute("Qualifiers")?.Value;

            var evt = new WindowsEvent
            {
                RawXml = xml,
                Properties = properties,
                LogName = NullableText.Clean(FindChild(system, "Channel")?.Value),
                ProviderName = NullableText.Clean(FindChild(system, "Provider")?.Attribute("Name")?.Value),
                EventId = ParseInt(eventIdElement?.Value) ?? 0,
                EventRecordId = ParseLong(FindChild(system, "EventRecordID")?.Value),
                TimeCreatedUtc = ParseTimestamp(FindChild(system, "TimeCreated")?.Attribute("SystemTime")?.Value),
                Level = MapLevel(FindChild(system, "Level")?.Value),
                ComputerName = NullableText.Clean(FindChild(system, "Computer")?.Value)
            };

            var userId = NullableText.Clean(FindChild(system, "Security")?.Attribute("UserID")?.Value);
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
        catch
        {
            return null;
        }
    }

    private static bool TryLoadDocument(string xml, out XDocument document, out XElement root)
    {
        document = null!;
        root = null!;
        try
        {
            using var textReader = new StringReader(xml);
            using var xmlReader = XmlReader.Create(textReader, new XmlReaderSettings
            {
                CheckCharacters = false,
                DtdProcessing = DtdProcessing.Prohibit,
                XmlResolver = null
            });
            document = XDocument.Load(xmlReader, LoadOptions.None);
            if (document.Root is not { } loadedRoot)
            {
                return false;
            }

            root = loadedRoot;
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static XElement? FindChild(XElement? parent, string localName) =>
        parent?.Elements().FirstOrDefault(element => element.Name.LocalName == localName);

    public static Dictionary<string, string> ExtractProperties(XElement? eventData)
    {
        var properties = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (eventData == null)
        {
            return properties;
        }

        var unnamedIndex = 0;
        foreach (var data in eventData.Descendants())
        {
            if (data.Name.LocalName is "EventData" or "UserData" or "Binary")
            {
                continue;
            }

            if (data.Name.LocalName != "Data" && data.HasElements)
            {
                AddNestedProperties(data, properties, prefix: null);
                continue;
            }

            var name = data.Attribute("Name")?.Value;
            if (string.IsNullOrWhiteSpace(name))
            {
                name = data.Name.LocalName != "Data"
                    ? data.Name.LocalName
                    : $"Data{unnamedIndex++}";
            }

            var value = data.Name.LocalName == "Binary"
                ? FormatBinaryValue(data.Value)
                : data.Value;
            if (string.IsNullOrEmpty(value))
            {
                continue;
            }

            properties[name] = value;
        }

        return properties;
    }

    private static string? FormatBinaryValue(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        try
        {
            return Convert.ToHexString(Convert.FromBase64String(value.Trim()));
        }
        catch
        {
            return value.Trim();
        }
    }

    private static void AddNestedProperties(
        XElement element,
        Dictionary<string, string> properties,
        string? prefix)
    {
        foreach (var child in element.Elements())
        {
            var name = string.IsNullOrEmpty(prefix)
                ? child.Name.LocalName
                : $"{prefix}.{child.Name.LocalName}";

            if (child.HasElements)
            {
                AddNestedProperties(child, properties, name);
                continue;
            }

            if (!string.IsNullOrEmpty(child.Value))
            {
                properties.TryAdd(name, child.Value);
            }
        }
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
