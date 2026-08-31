namespace WindowsIncidentAnalyzer.Infrastructure;

public static class AppPaths
{
    public static string ExecutableDirectory =>
        string.IsNullOrWhiteSpace(AppContext.BaseDirectory)
            ? Directory.GetCurrentDirectory()
            : Path.GetFullPath(AppContext.BaseDirectory);

    public static string DataDirectory
    {
        get
        {
            var nextToExe = Path.Combine(ExecutableDirectory, "data");
            if (CanUseDirectory(nextToExe))
            {
                return nextToExe;
            }

            var local = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "WindowsIncidentAnalyzer");
            Directory.CreateDirectory(local);
            return local;
        }
    }

    public static string ResolveRelative(string relativePath)
    {
        if (Path.IsPathRooted(relativePath))
        {
            return relativePath;
        }

        return Path.GetFullPath(Path.Combine(DataDirectory, relativePath));
    }

    public static string ConfigurationDirectory
    {
        get
        {
            var besideExe = Path.Combine(ExecutableDirectory, "Configuration");
            if (Directory.Exists(besideExe))
            {
                return besideExe;
            }

            var inCwd = Path.Combine(Directory.GetCurrentDirectory(), "Configuration");
            return Directory.Exists(inCwd) ? inCwd : besideExe;
        }
    }

    private static bool CanUseDirectory(string path)
    {
        try
        {
            Directory.CreateDirectory(path);
            var probe = Path.Combine(path, ".write-test");
            File.WriteAllText(probe, "ok");
            File.Delete(probe);
            return true;
        }
        catch
        {
            return false;
        }
    }
}
