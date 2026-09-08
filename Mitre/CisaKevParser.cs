using System.Text.Json;
using WindowsIncidentAnalyzer.Models;

namespace WindowsIncidentAnalyzer.Mitre;

public static class CisaKevParser
{
    public static IReadOnlyList<CveRecord> Parse(string json, string source)
    {
        using var document = JsonDocument.Parse(json);
        if (!document.RootElement.TryGetProperty("vulnerabilities", out var vulnerabilities))
        {
            return [];
        }

        var importedUtc = DateTime.UtcNow;
        var records = new List<CveRecord>();

        foreach (var item in vulnerabilities.EnumerateArray())
        {
            var cveId = ReadString(item, "cveID");
            if (string.IsNullOrWhiteSpace(cveId))
            {
                continue;
            }

            records.Add(new CveRecord
            {
                CveId = cveId.Trim().ToUpperInvariant(),
                VendorProject = ReadString(item, "vendorProject"),
                Product = ReadString(item, "product"),
                VulnerabilityName = ReadString(item, "vulnerabilityName"),
                ShortDescription = ReadString(item, "shortDescription"),
                RequiredAction = ReadString(item, "requiredAction"),
                DateAddedUtc = ParseDate(ReadString(item, "dateAdded")),
                DueDateUtc = ParseDate(ReadString(item, "dueDate")),
                KnownRansomwareUse = ReadString(item, "knownRansomwareCampaignUse"),
                Notes = ReadString(item, "notes"),
                Source = source,
                ImportedUtc = importedUtc
            });
        }

        return records;
    }

    private static DateTime? ParseDate(string? value) =>
        DateTime.TryParse(value, out var parsed)
            ? DateTime.SpecifyKind(parsed.Date, DateTimeKind.Utc)
            : null;

    private static string? ReadString(JsonElement element, string propertyName) =>
        element.TryGetProperty(propertyName, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;
}
