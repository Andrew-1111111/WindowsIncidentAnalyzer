using Microsoft.Extensions.Logging;
using WindowsIncidentAnalyzer.Infrastructure;
using WindowsIncidentAnalyzer.Mitre;
using WindowsIncidentAnalyzer.Repositories;

namespace WindowsIncidentAnalyzer.Services;

public sealed class CveDatabaseService(
    ICveRepository repository,
    IWebDownloadService webDownload,
    ILogger<CveDatabaseService> logger) : ICveDatabaseService
{
    private const string DefaultFileName = "known_exploited_vulnerabilities.json";
    private int _count;

    public int Count => _count;

    public async Task EnsureLoadedAsync(CancellationToken cancellationToken)
    {
        if (_count > 0)
        {
            return;
        }

        var records = await repository.GetAllAsync(cancellationToken);
        _count = records.Count;
        if (_count > 0)
        {
            return;
        }

        var cached = ResolveCachePath();
        if (File.Exists(cached))
        {
            await LoadFromFileAsync(cached, cancellationToken);
        }
    }

    public async Task<int> LoadFromFileAsync(string path, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var fullPath = Path.GetFullPath(path);
        if (!File.Exists(fullPath))
        {
            throw new FileNotFoundException($"CVE database file was not found: {fullPath}");
        }

        var json = await File.ReadAllTextAsync(fullPath, cancellationToken);
        var records = CisaKevParser.Parse(json, $"file:{fullPath}");
        await repository.ReplaceAllAsync(records, cancellationToken);
        _count = records.Count;
        logger.LogInformation("Loaded {Count} CVE record(s) from {Path}", records.Count, fullPath);
        return records.Count;
    }

    public async Task<int> UpdateFromCisaKevAsync(CancellationToken cancellationToken)
    {
        var cacheDirectory = Path.GetDirectoryName(ResolveCachePath())!;
        Directory.CreateDirectory(cacheDirectory);

        logger.LogInformation("Downloading CISA Known Exploited Vulnerabilities catalog...");
        var json = await webDownload.GetStringAsync(
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
            cancellationToken,
            WebDownloadClients.Cve);
        var cachePath = ResolveCachePath();
        await File.WriteAllTextAsync(cachePath, json, cancellationToken);

        var records = CisaKevParser.Parse(json, "CISA-KEV");
        await repository.ReplaceAllAsync(records, cancellationToken);
        _count = records.Count;
        logger.LogInformation("Loaded {Count} CVE record(s) from CISA KEV", records.Count);
        return records.Count;
    }

    private static string ResolveCachePath() =>
        Path.Combine(AppPaths.DataDirectory, "cve", DefaultFileName);
}
