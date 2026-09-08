using System.Text.Json;

namespace WindowsIncidentAnalyzer.Infrastructure;

public sealed class StartupCache
{
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    public DateTime? IocUpdatedUtc { get; set; }

    public DateTime? SigmaUpdatedUtc { get; set; }

    public DateTime? MitreUpdatedUtc { get; set; }

    public DateTime? CveUpdatedUtc { get; set; }

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

    public bool ShouldRefreshIoc(int refreshHours) => ShouldRefresh(IocUpdatedUtc, refreshHours);

    public bool ShouldRefreshSigma(int refreshHours) => ShouldRefresh(SigmaUpdatedUtc, refreshHours);

    public bool ShouldRefreshMitre(int refreshHours) => ShouldRefresh(MitreUpdatedUtc, refreshHours);

    public bool ShouldRefreshCve(int refreshHours) => ShouldRefresh(CveUpdatedUtc, refreshHours);

    private static bool ShouldRefresh(DateTime? updatedUtc, int refreshHours) =>
        refreshHours <= 0 ||
        updatedUtc is not { } updated ||
        DateTime.UtcNow - updated >= TimeSpan.FromHours(refreshHours);
}
