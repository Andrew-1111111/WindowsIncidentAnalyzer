using System.Text.Json;
using WindowsIncidentAnalyzer.Infrastructure;

namespace WindowsIncidentAnalyzer.Infrastructure;

public sealed class StartupCache
{
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    public DateTime? IocUpdatedUtc { get; set; }

    public DateTime? SigmaUpdatedUtc { get; set; }

    public static string CachePath => Path.Combine(AppPaths.DataDirectory, "startup-cache.json");

    public static StartupCache Load()
    {
        try
        {
            if (!File.Exists(CachePath))
            {
                return new StartupCache();
            }

            var json = File.ReadAllText(CachePath);
            return JsonSerializer.Deserialize<StartupCache>(json, JsonOptions) ?? new StartupCache();
        }
        catch
        {
            return new StartupCache();
        }
    }

    public void Save()
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(CachePath)!);
            File.WriteAllText(CachePath, JsonSerializer.Serialize(this, JsonOptions));
        }
        catch
        {
            // Cache is optional.
        }
    }

    public bool ShouldRefreshIoc(int refreshHours) =>
        refreshHours <= 0 || IocUpdatedUtc is not { } updated ||
        DateTime.UtcNow - updated >= TimeSpan.FromHours(refreshHours);

    public bool ShouldRefreshSigma(int refreshHours) =>
        refreshHours <= 0 || SigmaUpdatedUtc is not { } updated ||
        DateTime.UtcNow - updated >= TimeSpan.FromHours(refreshHours);
}
