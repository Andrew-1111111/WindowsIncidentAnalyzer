using System.IO.Compression;
using System.Net.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using WindowsIncidentAnalyzer.Configuration;
using WindowsIncidentAnalyzer.Infrastructure;
using WindowsIncidentAnalyzer.Repositories;
using WindowsIncidentAnalyzer.Sigma;
using WindowsIncidentAnalyzer.Sigma.Models;

namespace WindowsIncidentAnalyzer.Services;

public sealed class SigmaRuleService(
    ISigmaRuleRepository repository,
    IOptions<DetectionRulesOptions> options,
    IWebDownloadService webDownload,
    ILogger<SigmaRuleService> logger) : ISigmaRuleService
{
    private readonly SigmaYamlParser _parser = new();

    public IReadOnlyList<SigmaRule> GetRules() => repository.GetRules();

    public async Task EnsureLoadedAsync(CancellationToken cancellationToken)
    {
        LoadMetadataIfPresent();

        if (repository.Count > 0)
        {
            return;
        }

        var configured = ResolveRulesDirectory();
        if (!Directory.Exists(configured))
        {
            var sample = Path.Combine(AppPaths.ExecutableDirectory, "samples", "sigma");
            if (Directory.Exists(sample))
            {
                await LoadFromDirectoryAsync(sample, cancellationToken);
            }

            return;
        }

        await LoadFromDirectoryAsync(configured, cancellationToken);
    }

    public async Task<int> LoadFromDirectoryAsync(string directory, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var fullPath = Path.GetFullPath(directory);
        if (!Directory.Exists(fullPath))
        {
            throw new DirectoryNotFoundException($"Sigma rules directory was not found: {fullPath}");
        }

        LoadMetadataIfPresent(fullPath);
        var parsed = _parser.ParseDirectory(fullPath);
        var filtered = SigmaRuleFilter.Apply(parsed, options.Value.SigmaRules);
        await repository.ReplaceAsync(filtered, cancellationToken);
        logger.LogInformation("Loaded {Count} Sigma rule(s) from {Path}", filtered.Count, fullPath);
        return filtered.Count;
    }

    public Task<int> UpdateFromSigmaHqAsync(CancellationToken cancellationToken) =>
        UpdateFromHayabusaRulesAsync(cancellationToken);

    public async Task<int> UpdateFromHayabusaRulesAsync(CancellationToken cancellationToken)
    {
        var target = ResolveRulesDirectory();
        Directory.CreateDirectory(target);

        logger.LogInformation("Downloading Hayabusa rule set (hayabusa-rules)...");
        using var request = new HttpRequestMessage(HttpMethod.Get, HayabusaEventMetadata.RulesRepositoryZipUrl);
        using var response = await webDownload.SendAsync(
            request,
            HttpCompletionOption.ResponseHeadersRead,
            cancellationToken,
            WebDownloadClients.Sigma);
        response.EnsureSuccessStatusCode();

        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
        using var zip = new ZipArchive(stream, ZipArchiveMode.Read);
        var extracted = 0;
        foreach (var entry in zip.Entries)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (entry.Length == 0 || string.IsNullOrWhiteSpace(entry.Name))
            {
                continue;
            }

            if (!HayabusaRulesArchive.IsSupportedEntry(entry.FullName, entry.Name))
            {
                continue;
            }

            var relative = HayabusaRulesArchive.GetRelativePath(entry.FullName);
            if (relative == null)
            {
                continue;
            }

            var destination = Path.Combine(target, relative.Replace('/', Path.DirectorySeparatorChar));
            Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
            await using var source = entry.Open();
            await using var destinationStream = new FileStream(
                destination,
                FileMode.Create,
                FileAccess.Write,
                FileShare.None,
                bufferSize: 81920,
                useAsync: true);
            await source.CopyToAsync(destinationStream, cancellationToken);
            extracted++;
        }

        logger.LogInformation("Extracted {Count} Hayabusa file(s) to {Path}", extracted, target);
        LoadMetadataIfPresent(target);
        return await LoadFromDirectoryAsync(target, cancellationToken);
    }

    private void LoadMetadataIfPresent(string? rulesDirectory = null)
    {
        var candidates = new List<string>();
        if (!string.IsNullOrWhiteSpace(rulesDirectory))
        {
            candidates.Add(Path.Combine(rulesDirectory, "config"));
        }

        var configured = rulesDirectory ?? AppPaths.ResolveRelative(
            options.Value.SigmaRules.RulesPath);
        candidates.Add(Path.Combine(configured, "config"));

        foreach (var configDirectory in candidates.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            if (!Directory.Exists(configDirectory))
            {
                continue;
            }

            HayabusaEventMetadata.LoadFromConfigDirectory(configDirectory);
            if (HayabusaEventMetadata.IsLoaded)
            {
                return;
            }
        }
    }

    private string ResolveRulesDirectory()
    {
        var configured = options.Value.SigmaRules.RulesPath;
        return Path.IsPathRooted(configured)
            ? configured
            : AppPaths.ResolveRelative(configured);
    }
}
