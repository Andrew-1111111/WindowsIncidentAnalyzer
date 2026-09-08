namespace WindowsIncidentAnalyzer.Infrastructure;

internal static class HayabusaRulesArchive
{
    public static string? GetRelativePath(string entryFullName)
    {
        foreach (var marker in new[] { "/sigma/", "/hayabusa/", "/config/" })
        {
            var index = entryFullName.IndexOf(marker, StringComparison.OrdinalIgnoreCase);
            if (index >= 0)
            {
                return entryFullName[index..].TrimStart('/');
            }
        }

        return null;
    }

    public static bool IsSupportedEntry(string entryFullName, string entryName) =>
        !string.IsNullOrWhiteSpace(entryName) &&
        (entryName.EndsWith(".yml", StringComparison.OrdinalIgnoreCase) ||
         entryName.EndsWith(".yaml", StringComparison.OrdinalIgnoreCase) ||
         entryName.Equals("channel_eid_info.txt", StringComparison.OrdinalIgnoreCase) ||
         entryName.Equals("eventkey_alias.txt", StringComparison.OrdinalIgnoreCase)) &&
        GetRelativePath(entryFullName) != null;
}
