using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using WindowsIncidentAnalyzer.Configuration;

namespace WindowsIncidentAnalyzer.Infrastructure;

public static class ConfigurationLoader
{
    public static void Configure(HostApplicationBuilder builder)
    {
        var configDir = AppPaths.ConfigurationDirectory;
        builder.Configuration.Sources.Clear();
        builder.Configuration
            .AddJsonFile(Path.Combine(configDir, "appsettings.json"), optional: true, reloadOnChange: false)
            .AddJsonFile(Path.Combine(configDir, "DetectionRules.json"), optional: true, reloadOnChange: false)
            .AddJsonFile(Path.Combine(Directory.GetCurrentDirectory(), "Configuration", "appsettings.json"), optional: true, reloadOnChange: false)
            .AddJsonFile(Path.Combine(Directory.GetCurrentDirectory(), "Configuration", "DetectionRules.json"), optional: true, reloadOnChange: false)
            .AddEnvironmentVariables("WIA_");
    }

    public static string ResolveDatabasePath(AnalyzerOptions options)
    {
        var configured = string.IsNullOrWhiteSpace(options.Database.Path)
            ? "data/investigation.db"
            : options.Database.Path;

        if (Path.IsPathRooted(configured))
        {
            return configured;
        }

        return Path.GetFullPath(Path.Combine(AppPaths.DataDirectory, Path.GetFileName(configured) is { Length: > 0 } name
            ? name
            : "investigation.db"));
    }
}
