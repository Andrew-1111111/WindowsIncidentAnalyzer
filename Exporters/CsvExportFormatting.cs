using System.Globalization;
using System.Text.Json;

namespace WindowsIncidentAnalyzer.Exporters;

internal static class CsvExportFormatting
{
    private const int MaxCellLength = 32_000;

    public static string FormatUtc(DateTime value) =>
        value.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture);

    public static string FormatIds(IReadOnlyList<long> ids) =>
        ids.Count == 0 ? string.Empty : string.Join(", ", ids);

    public static string FormatList(IReadOnlyList<string> values) =>
        values.Count == 0 ? string.Empty : string.Join(" | ", values.Select(Cell));

    public static string FormatNullableBool(bool? value) =>
        value switch
        {
            true => "yes",
            false => "no",
            _ => string.Empty
        };

    public static string FormatProperties(IReadOnlyDictionary<string, string> properties)
    {
        if (properties.Count == 0)
        {
            return string.Empty;
        }

        return Cell(JsonSerializer.Serialize(properties));
    }

    public static string Cell(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return string.Empty;
        }

        var normalized = value
            .Replace("\r\n", " ", StringComparison.Ordinal)
            .Replace('\r', ' ')
            .Replace('\n', ' ')
            .Replace('\t', ' ')
            .Trim();

        return normalized.Length <= MaxCellLength
            ? normalized
            : normalized[..MaxCellLength];
    }
}
