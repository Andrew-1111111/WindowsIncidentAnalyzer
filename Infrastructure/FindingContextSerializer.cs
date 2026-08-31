using System.Text.Json;
using System.Text.Json.Serialization;
using WindowsIncidentAnalyzer.Models;

namespace WindowsIncidentAnalyzer.Infrastructure;

public static class FindingContextSerializer
{
    private static readonly JsonSerializerOptions Options = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Converters = { new JsonStringEnumConverter() }
    };

    public static string? Serialize(FindingContext? context)
    {
        if (context == null)
        {
            return null;
        }

        return JsonSerializer.Serialize(context, Options);
    }

    public static FindingContext Deserialize(string? json)
    {
        if (string.IsNullOrWhiteSpace(json))
        {
            return new FindingContext();
        }

        try
        {
            return JsonSerializer.Deserialize<FindingContext>(json, Options) ?? new FindingContext();
        }
        catch (JsonException)
        {
            return new FindingContext();
        }
    }
}
