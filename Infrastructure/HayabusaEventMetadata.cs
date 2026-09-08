using System.Globalization;
using System.Text;

namespace WindowsIncidentAnalyzer.Infrastructure;

/// <summary>
/// Hayabusa hayabusa-rules config: channel/event titles and event field aliases.
/// </summary>
public static class HayabusaEventMetadata
{
    public const string RulesRepositoryZipUrl =
        "https://github.com/Yamato-Security/hayabusa-rules/archive/refs/heads/main.zip";

    private static readonly Dictionary<(string Channel, int EventId), string> EventTitles =
        new(ChannelEventComparer.Instance);

    private static readonly Dictionary<string, string> AliasToLeaf =
        new(StringComparer.OrdinalIgnoreCase);

    private static readonly object Sync = new();

    public static bool IsLoaded => EventTitles.Count > 0 || AliasToLeaf.Count > 0;

    public static void LoadFromConfigDirectory(string configDirectory)
    {
        if (string.IsNullOrWhiteSpace(configDirectory) || !Directory.Exists(configDirectory))
        {
            return;
        }

        var channelInfo = Path.Combine(configDirectory, "channel_eid_info.txt");
        var aliases = Path.Combine(configDirectory, "eventkey_alias.txt");

        lock (Sync)
        {
            EventTitles.Clear();
            AliasToLeaf.Clear();

            if (File.Exists(channelInfo))
            {
                LoadChannelEventInfo(channelInfo);
            }

            if (File.Exists(aliases))
            {
                LoadEventKeyAliases(aliases);
            }
        }
    }

    public static bool TryGetEventTitle(string? channel, int eventId, out string title)
    {
        title = string.Empty;
        if (string.IsNullOrWhiteSpace(channel))
        {
            return false;
        }

        lock (Sync)
        {
            return EventTitles.TryGetValue((channel.Trim(), eventId), out title!);
        }
    }

    public static string? ResolveLeafFieldName(string aliasOrField)
    {
        if (string.IsNullOrWhiteSpace(aliasOrField))
        {
            return null;
        }

        lock (Sync)
        {
            if (AliasToLeaf.TryGetValue(aliasOrField, out var leaf))
            {
                return leaf;
            }
        }

        return aliasOrField.Contains('.', StringComparison.Ordinal)
            ? aliasOrField.Split('.')[^1]
            : aliasOrField;
    }

    public static void ApplyFieldAliases(IDictionary<string, string> fields)
    {
        if (fields.Count == 0)
        {
            return;
        }

        lock (Sync)
        {
            foreach (var (alias, leaf) in AliasToLeaf)
            {
                if (fields.TryGetValue(leaf, out var value) && !string.IsNullOrWhiteSpace(value))
                {
                    fields[alias] = value;
                }
            }
        }
    }

    public static IEnumerable<string> GetLookupNames(string fieldName)
    {
        if (string.IsNullOrWhiteSpace(fieldName))
        {
            yield break;
        }

        yield return fieldName;

        var leaf = fieldName.Contains('.', StringComparison.Ordinal)
            ? fieldName.Split('.')[^1]
            : fieldName;
        if (!leaf.Equals(fieldName, StringComparison.OrdinalIgnoreCase))
        {
            yield return leaf;
        }

        List<string> aliases;
        lock (Sync)
        {
            aliases = AliasToLeaf
                .Where(pair => pair.Value.Equals(leaf, StringComparison.OrdinalIgnoreCase))
                .Select(pair => pair.Key)
                .ToList();
        }

        foreach (var alias in aliases)
        {
            yield return alias;
        }
    }

    internal static void LoadChannelEventInfo(string path)
    {
        foreach (var line in File.ReadLines(path))
        {
            if (string.IsNullOrWhiteSpace(line) || line.StartsWith("Channel,", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            var parts = SplitCsvLine(line);
            if (parts.Count < 3)
            {
                continue;
            }

            if (!int.TryParse(parts[1].Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture, out var eventId))
            {
                continue;
            }

            var title = parts[2].Trim();
            if (title.Length == 0)
            {
                continue;
            }

            EventTitles[(parts[0].Trim(), eventId)] = title;
        }
    }

    internal static void LoadEventKeyAliases(string path)
    {
        foreach (var line in File.ReadLines(path))
        {
            if (string.IsNullOrWhiteSpace(line))
            {
                continue;
            }

            var comma = line.IndexOf(',');
            if (comma <= 0)
            {
                continue;
            }

            var alias = line[..comma].Trim();
            var target = line[(comma + 1)..].Trim();
            if (alias.Length == 0 || target.Length == 0)
            {
                continue;
            }

            var leaf = target.Split('.')[^1];
            AliasToLeaf[alias] = leaf;
        }
    }

    private static List<string> SplitCsvLine(string line)
    {
        var parts = new List<string>();
        var current = new StringBuilder();
        var inQuotes = false;
        foreach (var ch in line)
        {
            if (ch == '"')
            {
                inQuotes = !inQuotes;
                continue;
            }

            if (ch == ',' && !inQuotes)
            {
                parts.Add(current.ToString());
                current.Clear();
                continue;
            }

            current.Append(ch);
        }

        parts.Add(current.ToString());
        return parts;
    }

    private sealed class ChannelEventComparer : IEqualityComparer<(string Channel, int EventId)>
    {
        public static readonly ChannelEventComparer Instance = new();

        public bool Equals((string Channel, int EventId) x, (string Channel, int EventId) y) =>
            x.EventId == y.EventId &&
            x.Channel.Equals(y.Channel, StringComparison.OrdinalIgnoreCase);

        public int GetHashCode((string Channel, int EventId) obj) =>
            HashCode.Combine(StringComparer.OrdinalIgnoreCase.GetHashCode(obj.Channel), obj.EventId);
    }
}
