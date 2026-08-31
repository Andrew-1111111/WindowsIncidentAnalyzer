using System.Globalization;
using System.Text.RegularExpressions;
using WindowsIncidentAnalyzer.Models;
using WindowsIncidentAnalyzer.Sigma.Models;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

namespace WindowsIncidentAnalyzer.Sigma;

public sealed class SigmaYamlParser
{
    private static readonly IDeserializer Deserializer = new DeserializerBuilder()
        .WithNamingConvention(UnderscoredNamingConvention.Instance)
        .IgnoreUnmatchedProperties()
        .Build();

    public IReadOnlyList<SigmaRule> ParseFile(string path)
    {
        var yaml = File.ReadAllText(path);
        return ParseDocuments(yaml, path);
    }

    public IReadOnlyList<SigmaRule> ParseDocuments(string yaml, string sourcePath)
    {
        var rules = new List<SigmaRule>();
        foreach (var document in SplitDocuments(yaml))
        {
            if (string.IsNullOrWhiteSpace(document))
            {
                continue;
            }

            try
            {
                var raw = Deserializer.Deserialize<RawSigmaRule>(document);
                if (raw?.Detection == null || string.IsNullOrWhiteSpace(raw.Title))
                {
                    continue;
                }

                var rule = Map(raw, sourcePath);
                if (rule.Selections.Count == 0 || string.IsNullOrWhiteSpace(rule.Condition))
                {
                    continue;
                }

                rules.Add(rule);
            }
            catch
            {
                // Skip malformed rule files.
            }
        }

        return rules;
    }

    public IReadOnlyList<SigmaRule> ParseDirectory(string directory)
    {
        var rules = new List<SigmaRule>();
        if (!Directory.Exists(directory))
        {
            return rules;
        }

        foreach (var file in Directory.EnumerateFiles(directory, "*.yml", SearchOption.AllDirectories)
                     .Concat(Directory.EnumerateFiles(directory, "*.yaml", SearchOption.AllDirectories)))
        {
            rules.AddRange(ParseFile(file));
        }

        return rules;
    }

    private static SigmaRule Map(RawSigmaRule raw, string sourcePath)
    {
        var rule = new SigmaRule
        {
            Title = raw.Title.Trim(),
            Id = raw.Id,
            Description = raw.Description,
            Status = raw.Status,
            Author = raw.Author,
            SourcePath = sourcePath,
            Severity = MapSeverity(raw.Level),
            Tags = raw.Tags ?? [],
            Logsource = new SigmaLogsource
            {
                Product = GetString(raw.Logsource, "product"),
                Service = GetString(raw.Logsource, "service"),
                Category = GetString(raw.Logsource, "category"),
                Definition = GetString(raw.Logsource, "definition")
            }
        };

        foreach (var (name, value) in raw.Detection!)
        {
            if (name.Equals("condition", StringComparison.OrdinalIgnoreCase))
            {
                rule.Condition = Convert.ToString(value, CultureInfo.InvariantCulture) ?? string.Empty;
                continue;
            }

            if (name.Equals("timeframe", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            rule.Selections[name] = ParseSelection(value);
        }

        rule.RelevantEventIds = SigmaLogsourceCatalog.ResolveEventIds(rule.Logsource);
        return rule;
    }

    private static SigmaSelection ParseSelection(object? value)
    {
        return value switch
        {
            string keyword => new SigmaSelection { Keywords = [keyword] },
            IEnumerable<object> list when list.All(item => item is string) =>
                new SigmaSelection { Keywords = list.Cast<string>().ToList() },
            IDictionary<object, object> map => ParseFieldSelection(map),
            _ => new SigmaSelection()
        };
    }

    private static SigmaSelection ParseFieldSelection(IDictionary<object, object> map)
    {
        var selection = new SigmaSelection();
        foreach (var (rawKey, rawValue) in map)
        {
            var key = Convert.ToString(rawKey, CultureInfo.InvariantCulture) ?? string.Empty;
            if (string.IsNullOrWhiteSpace(key))
            {
                continue;
            }

            var (field, modifier) = ParseFieldKey(key);
            selection.FieldMatches.Add(new SigmaFieldMatch
            {
                Field = field,
                Modifier = modifier,
                Values = NormalizeValues(rawValue)
            });
        }

        return selection;
    }

    private static (string Field, SigmaFieldModifier Modifier) ParseFieldKey(string key)
    {
        var parts = key.Split('|', 2, StringSplitOptions.TrimEntries);
        var field = parts[0];
        if (parts.Length == 1)
        {
            return (field, SigmaFieldModifier.Equals);
        }

        var modifier = parts[1].ToLowerInvariant() switch
        {
            "contains" => SigmaFieldModifier.Contains,
            "startswith" => SigmaFieldModifier.StartsWith,
            "endswith" => SigmaFieldModifier.EndsWith,
            "re" or "regex" => SigmaFieldModifier.Regex,
            _ => SigmaFieldModifier.Equals
        };
        return (field, modifier);
    }

    private static List<string> NormalizeValues(object? value) =>
        value switch
        {
            null => [],
            string text => [text],
            IEnumerable<object> items => items.Select(item => Convert.ToString(item, CultureInfo.InvariantCulture) ?? string.Empty)
                .Where(item => !string.IsNullOrWhiteSpace(item))
                .ToList(),
            _ => [Convert.ToString(value, CultureInfo.InvariantCulture) ?? string.Empty]
        };

    private static DetectionSeverity MapSeverity(string? level) =>
        (level ?? "medium").Trim().ToLowerInvariant() switch
        {
            "informational" or "info" => DetectionSeverity.Info,
            "low" => DetectionSeverity.Low,
            "high" => DetectionSeverity.High,
            "critical" => DetectionSeverity.Critical,
            _ => DetectionSeverity.Medium
        };

    private static string? GetString(IDictionary<object, object>? map, string key)
    {
        if (map == null)
        {
            return null;
        }

        foreach (var (rawKey, value) in map)
        {
            if (string.Equals(Convert.ToString(rawKey, CultureInfo.InvariantCulture), key, StringComparison.OrdinalIgnoreCase))
            {
                return Convert.ToString(value, CultureInfo.InvariantCulture);
            }
        }

        return null;
    }

    private static IEnumerable<string> SplitDocuments(string yaml)
    {
        var parts = Regex.Split(yaml, @"^\s*---\s*$", RegexOptions.Multiline);
        return parts.Where(part => !string.IsNullOrWhiteSpace(part));
    }

    private sealed class RawSigmaRule
    {
        public string Title { get; set; } = string.Empty;

        public string? Id { get; set; }

        public string? Description { get; set; }

        public string? Status { get; set; }

        public string? Author { get; set; }

        public Dictionary<object, object>? Logsource { get; set; }

        public Dictionary<string, object>? Detection { get; set; }

        public string? Level { get; set; }

        public List<string>? Tags { get; set; }
    }
}
