using Microsoft.Extensions.Logging;
using WindowsIncidentAnalyzer.Infrastructure;
using WindowsIncidentAnalyzer.Mitre;
using WindowsIncidentAnalyzer.Repositories;

namespace WindowsIncidentAnalyzer.Services;

public sealed class MitreAttackService(
    IMitreAttackRepository repository,
    IWebDownloadService webDownload,
    ILogger<MitreAttackService> logger) : IMitreAttackService
{
    private const string DefaultFileName = "enterprise-attack.json";

    public async Task EnsureLoadedAsync(CancellationToken cancellationToken)
    {
        if (repository.TechniqueCount > 0)
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
            throw new FileNotFoundException($"MITRE ATT&CK database was not found: {fullPath}");
        }

        var json = await File.ReadAllTextAsync(fullPath, cancellationToken);
        var catalog = MitreAttackStixParser.Parse(json);
        await repository.ReplaceAsync(catalog.Tactics, catalog.Techniques, cancellationToken);
        logger.LogInformation(
            "Loaded MITRE ATT&CK catalog: {TacticCount} tactic(s), {TechniqueCount} technique(s) from {Path}",
            catalog.Tactics.Count,
            catalog.Techniques.Count,
            fullPath);
        return catalog.Techniques.Count;
    }

    public async Task<int> UpdateFromMitreCtiAsync(CancellationToken cancellationToken)
    {
        var cacheDirectory = Path.GetDirectoryName(ResolveCachePath())!;
        Directory.CreateDirectory(cacheDirectory);

        logger.LogInformation("Downloading MITRE ATT&CK enterprise bundle...");
        var json = await webDownload.GetStringAsync(
            "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json",
            cancellationToken,
            WebDownloadClients.Mitre);
        var cachePath = ResolveCachePath();
        await File.WriteAllTextAsync(cachePath, json, cancellationToken);
        return await LoadFromFileAsync(cachePath, cancellationToken);
    }

    public IReadOnlyList<Models.MitreAttackTechnique> GetTechniques() => repository.GetTechniques();

    public IReadOnlyList<Models.MitreAttackTactic> GetTactics() => repository.GetTactics();

    public bool TryGetTechnique(string techniqueId, out Models.MitreAttackTechnique technique) =>
        repository.TryGetTechnique(techniqueId, out technique);

    public bool TryGetTactic(string shortName, out Models.MitreAttackTactic tactic) =>
        repository.TryGetTactic(shortName, out tactic);

    private static string ResolveCachePath() =>
        Path.Combine(AppPaths.DataDirectory, "mitre", DefaultFileName);
}
