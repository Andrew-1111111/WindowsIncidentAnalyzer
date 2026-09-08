namespace WindowsIncidentAnalyzer.Exporters;

internal static class ExportPath
{
    /// <summary>
    /// Creates the parent directory for <paramref name="path"/> if needed and returns it.
    /// </summary>
    public static string? EnsureDirectory(string path)
    {
        var directory = Path.GetDirectoryName(Path.GetFullPath(path));
        if (!string.IsNullOrEmpty(directory))
        {
            Directory.CreateDirectory(directory);
        }

        return directory;
    }
}
