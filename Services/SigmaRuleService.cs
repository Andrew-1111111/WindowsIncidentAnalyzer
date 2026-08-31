using System.IO.Compression;
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
    ILogger<SigmaRuleService> logger) : ISigmaRuleService
{
    private static readonly HttpClient Http = CreateClient();
    private readonly SigmaYamlParser _parser = new();

    public IReadOnlyList<SigmaRule> GetRules() => repository.GetRules();

    public async Task EnsureLoadedAsync(CancellationToken cancellationToken)
    {
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

        var parsed = _parser.ParseDirectory(fullPath);
        var filtered = FilterRules(parsed);
        await repository.ReplaceAsync(filtered, cancellationToken);
        logger.LogInformation("Loaded {Count} Sigma rule(s) from {Path}", filtered.Count, fullPath);
        return filtered.Count;
    }

    public async Task<int> UpdateFromSigmaHqAsync(CancellationToken cancellationToken)
    {
        var target = ResolveRulesDirectory();
        Directory.CreateDirectory(target);

        logger.LogInformation("Downloading SigmaHQ rule set...");
        using var response = await Http.GetAsync(
            "https://github.com/SigmaHQ/sigma/archive/refs/heads/master.zip",
            HttpCompletionOption.ResponseHeadersRead,
            cancellationToken);
        response.EnsureSuccessStatusCode();

        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
        using var zip = new ZipArchive(stream, ZipArchiveMode.Read);
        var extracted = 0;
        foreach (var entry in zip.Entries)
        {
            if (!entry.FullName.Contains("/rules/windows/", StringComparison.OrdinalIgnoreCase) &&
                !entry.FullName.Contains("/rules-emerging-threats/", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            if (!entry.Name.EndsWith(".yml", StringComparison.OrdinalIgnoreCase) &&
                !entry.Name.EndsWith(".yaml", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            var relative = entry.FullName[(entry.FullName.IndexOf("/rules", StringComparison.Ordinal) + 1)..];
            var destination = Path.Combine(target, relative.Replace('/', Path.DirectorySeparatorChar));
            Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
            entry.ExtractToFile(destination, overwrite: true);
            extracted++;
        }

        logger.LogInformation("Extracted {Count} Sigma YAML file(s) to {Path}", extracted, target);
        return await LoadFromDirectoryAsync(target, cancellationToken);
    }

    private List<SigmaRule> FilterRules(IReadOnlyList<SigmaRule> rules)
    {
        var sigma = options.Value.SigmaRules;
        return rules
            .Where(rule => sigma.IncludeExperimental || !IsStatus(rule, "experimental"))
            .Where(rule => sigma.IncludeDeprecated || !IsStatus(rule, "deprecated"))
            .Where(rule => sigma.IncludeUnsupported || !IsStatus(rule, "unsupported"))
            .Where(rule => string.IsNullOrWhiteSpace(rule.Logsource.Product) ||
                           rule.Logsource.Product.Equals("windows", StringComparison.OrdinalIgnoreCase))
            .ToList();
    }

    private static bool IsStatus(SigmaRule rule, string status) =>
        string.Equals(rule.Status, status, StringComparison.OrdinalIgnoreCase);

    private string ResolveRulesDirectory()
    {
        var configured = options.Value.SigmaRules.RulesPath;
        return Path.IsPathRooted(configured)
            ? configured
            : AppPaths.ResolveRelative(configured);
    }

    private static HttpClient CreateClient()
    {
        var client = new HttpClient { Timeout = TimeSpan.FromMinutes(5) };
        client.DefaultRequestHeaders.UserAgent.ParseAdd("WindowsIncidentAnalyzer/1.0 (defensive DFIR; +local investigation)");
        return client;
    }
}
