using System.Text.Json;
using WindowsIncidentAnalyzer.Models;

namespace WindowsIncidentAnalyzer.Services;

public static class IocFeedParsers
{
    public static IEnumerable<Ioc> ParseSpamhausDrop(string body, string source)
    {
        using var reader = new StringReader(body);
        while (reader.ReadLine() is { } line)
        {
            line = line.Trim();
            if (line.Length == 0)
            {
                continue;
            }

            JsonDocument doc;
            try
            {
                doc = JsonDocument.Parse(line);
            }
            catch (JsonException)
            {
                continue;
            }

            using (doc)
            {
                if (doc.RootElement.ValueKind != JsonValueKind.Object)
                {
                    continue;
                }

                var cidr = doc.RootElement.TryGetProperty("cidr", out var cidrEl) ? cidrEl.GetString() : null;
                if (string.IsNullOrWhiteSpace(cidr))
                {
                    continue;
                }

                var ip = cidr.Split('/')[0];
                yield return new Ioc { Type = "ip", Value = ip, Source = source, Comment = "Spamhaus DROP network origin" };
            }
        }
    }
}
