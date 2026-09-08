using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Spectre.Console;
using WindowsIncidentAnalyzer.Configuration;
using WindowsIncidentAnalyzer.Data;
using WindowsIncidentAnalyzer.Repositories;
using WindowsIncidentAnalyzer.Services;

namespace WindowsIncidentAnalyzer.Infrastructure;

public static class ApplicationBootstrap
{
    public static async Task RunAsync(IServiceProvider services, string[] args, CancellationToken cancellationToken)
    {
        if (IsHelpOrVersion(args))
        {
            return;
        }

        await WriteInvestigationDatabaseSummaryAsync(services, cancellationToken);

        if (ShouldSkipThreatIntel(args))
        {
            return;
        }

        var startup = services.GetRequiredService<IOptions<AnalyzerOptions>>().Value.Startup;
        if (!startup.AutoUpdateIocFeeds &&
            !startup.AutoUpdateSigmaRules &&
            !startup.AutoUpdateMitreAttack &&
            !startup.AutoUpdateCveDatabase)
        {
            return;
        }

        var cache = StartupCache.Load();
        var iocNeeded = startup.AutoUpdateIocFeeds && cache.ShouldRefreshIoc(startup.IocRefreshHours);
        var sigmaNeeded = startup.AutoUpdateSigmaRules && cache.ShouldRefreshSigma(startup.SigmaRefreshHours);
        var mitreNeeded = startup.AutoUpdateMitreAttack && cache.ShouldRefreshMitre(startup.MitreRefreshHours);
        var cveNeeded = startup.AutoUpdateCveDatabase && cache.ShouldRefreshCve(startup.CveRefreshHours);

        if (!iocNeeded && !sigmaNeeded && !mitreNeeded && !cveNeeded)
        {
            var status = await EnsureLocalThreatIntelAsync(services, cancellationToken);
            if (startup.AutoUpdateIocFeeds && status.IocCount == 0)
            {
                iocNeeded = true;
            }

            if (startup.AutoUpdateSigmaRules && status.SigmaRuleCount == 0)
            {
                sigmaNeeded = true;
            }

            if (startup.AutoUpdateMitreAttack && status.MitreTechniqueCount == 0)
            {
                mitreNeeded = true;
            }

            if (startup.AutoUpdateCveDatabase && status.CveCount == 0)
            {
                cveNeeded = true;
            }

            if (!iocNeeded && !sigmaNeeded && !mitreNeeded && !cveNeeded)
            {
                WriteLine(
                    $"Threat intelligence ready: {status.IocCount:N0} IOC(s), {status.SigmaRuleCount:N0} Sigma rule(s), " +
                    $"{status.MitreTechniqueCount:N0} MITRE technique(s), {status.CveCount:N0} CVE record(s) - cached.");
                WriteNextOnlineUpdates(startup, cache);
                WriteLine(string.Empty);
                return;
            }
        }

        WriteLine(iocNeeded || sigmaNeeded || mitreNeeded || cveNeeded
            ? "Initializing threat intelligence..."
            : "Loading local threat intelligence...");

        var tasks = new List<Task<string>>();
        if (iocNeeded)
        {
            tasks.Add(UpdateIocAsync(services, cache, cancellationToken));
        }

        if (sigmaNeeded)
        {
            tasks.Add(UpdateSigmaAsync(services, cache, cancellationToken));
        }

        if (mitreNeeded)
        {
            tasks.Add(UpdateMitreAsync(services, cache, cancellationToken));
        }

        if (cveNeeded)
        {
            tasks.Add(UpdateCveAsync(services, cache, cancellationToken));
        }

        foreach (var result in await Task.WhenAll(tasks))
        {
            WriteResult(result);
        }

        var finalStatus = await EnsureLocalThreatIntelAsync(services, cancellationToken);
        WriteLine(
            $"Ready: {finalStatus.IocCount:N0} IOC(s), {finalStatus.SigmaRuleCount:N0} Sigma rule(s), " +
            $"{finalStatus.MitreTechniqueCount:N0} MITRE technique(s), {finalStatus.CveCount:N0} CVE record(s).");

        cache.Save();
        WriteLine(string.Empty);
    }

    private static async Task WriteInvestigationDatabaseSummaryAsync(
        IServiceProvider services,
        CancellationToken cancellationToken)
    {
        try
        {
            var database = services.GetRequiredService<InvestigationDatabase>();
            await database.EnsureInitializedAsync(cancellationToken);
            var factory = services.GetRequiredService<IDbContextFactory<InvestigationDbContext>>();
            await using var db = await factory.CreateDbContextAsync(cancellationToken);

            var eventCount = await db.Events.AsNoTracking().CountAsync(cancellationToken);
            var findingCount = await db.Findings.AsNoTracking().CountAsync(cancellationToken);
            var correlationCount = await db.Correlations.AsNoTracking().CountAsync(cancellationToken);
            var incidentCount = await db.Incidents.AsNoTracking().CountAsync(cancellationToken);
            var iocCount = await db.Iocs.AsNoTracking().CountAsync(cancellationToken);
            var cveCount = await db.Cves.AsNoTracking().CountAsync(cancellationToken);

            DateTime? fromUtc = null;
            DateTime? toUtc = null;
            if (eventCount > 0)
            {
                fromUtc = await db.Events.AsNoTracking().MinAsync(e => e.TimeCreatedUtc, cancellationToken);
                toUtc = await db.Events.AsNoTracking().MaxAsync(e => e.TimeCreatedUtc, cancellationToken);
            }

            WriteLine($"Investigation database: {database.DatabasePath}");
            if (eventCount == 0)
            {
                WriteLine("  No event logs collected yet. Run: collect");
            }
            else
            {
                WriteLine($"  Collected {eventCount:N0} event log record(s).");
                if (fromUtc is { } from && toUtc is { } to)
                {
                    WriteLine($"  Time range (UTC): {from:yyyy-MM-dd HH:mm:ss} .. {to:yyyy-MM-dd HH:mm:ss}");
                }
            }

            WriteLine(
                $"  Findings: {findingCount:N0} | Correlations: {correlationCount:N0} | Incidents: {incidentCount:N0} | " +
                $"IOCs: {iocCount:N0} | CVE records: {cveCount:N0}");
            WriteLine(string.Empty);
        }
        catch (Exception ex)
        {
            WriteLine($"Investigation database: unavailable ({ex.Message})");
            WriteLine(string.Empty);
        }
    }

    private static async Task<ThreatIntelStatus> EnsureLocalThreatIntelAsync(
        IServiceProvider services,
        CancellationToken cancellationToken)
    {
        var sigma = services.GetRequiredService<ISigmaRuleService>();
        await sigma.EnsureLoadedAsync(cancellationToken);

        var mitre = services.GetRequiredService<IMitreAttackService>();
        await mitre.EnsureLoadedAsync(cancellationToken);

        var cve = services.GetRequiredService<ICveDatabaseService>();
        await cve.EnsureLoadedAsync(cancellationToken);

        var iocRepo = services.GetRequiredService<IIocRepository>();
        var iocCount = (await iocRepo.GetAllAsync(cancellationToken)).Count;
        var sigmaCount = sigma.GetRules().Count;
        var mitreCount = mitre.GetTechniques().Count;
        var cveCount = cve.Count;

        return new ThreatIntelStatus(iocCount, sigmaCount, mitreCount, cveCount);
    }

    private static void WriteNextOnlineUpdates(StartupOptions startup, StartupCache cache)
    {
        WriteLine("Next online update:");
        if (startup.AutoUpdateIocFeeds)
        {
            WriteLine($"  IOC: after {FormatNextRefresh(cache.IocUpdatedUtc, startup.IocRefreshHours)}");
        }

        if (startup.AutoUpdateSigmaRules)
        {
            WriteLine($"  Sigma: after {FormatNextRefresh(cache.SigmaUpdatedUtc, startup.SigmaRefreshHours)}");
        }

        if (startup.AutoUpdateMitreAttack)
        {
            WriteLine($"  MITRE: after {FormatNextRefresh(cache.MitreUpdatedUtc, startup.MitreRefreshHours)}");
        }

        if (startup.AutoUpdateCveDatabase)
        {
            WriteLine($"  CVE: after {FormatNextRefresh(cache.CveUpdatedUtc, startup.CveRefreshHours)}");
        }
    }

    private static string FormatNextRefresh(DateTime? updatedUtc, int refreshHours)
    {
        if (refreshHours <= 0)
        {
            return "always";
        }

        if (updatedUtc is not { } updated)
        {
            return "now";
        }

        var next = updated.AddHours(refreshHours);
        return next <= DateTime.UtcNow
            ? "now"
            : $"{next:yyyy-MM-dd HH:mm} UTC";
    }

    private readonly record struct ThreatIntelStatus(
        int IocCount,
        int SigmaRuleCount,
        int MitreTechniqueCount,
        int CveCount);

    private static async Task<string> UpdateIocAsync(
        IServiceProvider services,
        StartupCache cache,
        CancellationToken cancellationToken)
    {
        try
        {
            WriteLine("IOC: downloading public feeds...");
            var progress = new Progress<string>(WriteProgress);
            var iocs = await services.GetRequiredService<IIocFeedService>().DownloadAsync(cancellationToken, progress);
            WriteLine($"IOC: saving {iocs.Count:N0} indicator(s) to database...");
            await services.GetRequiredService<IIocRepository>().ReplaceAllAsync(iocs, cancellationToken);
            cache.IocUpdatedUtc = DateTime.UtcNow;
            return $"IOC: {iocs.Count:N0} indicator(s) ready";
        }
        catch (Exception ex)
        {
            return $"IOC: update failed ({ex.Message})";
        }
    }

    private static async Task<string> UpdateSigmaAsync(
        IServiceProvider services,
        StartupCache cache,
        CancellationToken cancellationToken)
    {
        try
        {
            WriteLine("Sigma: downloading rules from Hayabusa (hayabusa-rules)...");
            var sigma = services.GetRequiredService<ISigmaRuleService>();
            var count = await sigma.UpdateFromHayabusaRulesAsync(cancellationToken);
            cache.SigmaUpdatedUtc = DateTime.UtcNow;
            return $"Sigma: {count:N0} rule(s) ready";
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or IOException)
        {
            var sigma = services.GetRequiredService<ISigmaRuleService>();
            await sigma.EnsureLoadedAsync(cancellationToken);
            var count = sigma.GetRules().Count;
            cache.SigmaUpdatedUtc = DateTime.UtcNow;
            return $"Sigma: {count:N0} local rule(s) ready (online update failed)";
        }
        catch (Exception ex)
        {
            return $"Sigma: update failed ({ex.Message})";
        }
    }

    private static async Task<string> UpdateMitreAsync(
        IServiceProvider services,
        StartupCache cache,
        CancellationToken cancellationToken) =>
        await UpdateCatalogWithLocalFallbackAsync(
            label: "MITRE",
            progressMessage: "MITRE: downloading ATT&CK enterprise bundle...",
            updateAsync: () => services.GetRequiredService<IMitreAttackService>().UpdateFromMitreCtiAsync(cancellationToken),
            loadLocalAsync: async () =>
            {
                var mitre = services.GetRequiredService<IMitreAttackService>();
                await mitre.EnsureLoadedAsync(cancellationToken);
                return mitre.GetTechniques().Count;
            },
            successSuffix: "technique(s)",
            onSuccess: () => cache.MitreUpdatedUtc = DateTime.UtcNow);

    private static async Task<string> UpdateCveAsync(
        IServiceProvider services,
        StartupCache cache,
        CancellationToken cancellationToken) =>
        await UpdateCatalogWithLocalFallbackAsync(
            label: "CVE",
            progressMessage: "CVE: downloading CISA Known Exploited Vulnerabilities catalog...",
            updateAsync: () => services.GetRequiredService<ICveDatabaseService>().UpdateFromCisaKevAsync(cancellationToken),
            loadLocalAsync: async () =>
            {
                var cve = services.GetRequiredService<ICveDatabaseService>();
                await cve.EnsureLoadedAsync(cancellationToken);
                return cve.Count;
            },
            successSuffix: "record(s)",
            onSuccess: () => cache.CveUpdatedUtc = DateTime.UtcNow);

    private static async Task<string> UpdateCatalogWithLocalFallbackAsync(
        string label,
        string progressMessage,
        Func<Task<int>> updateAsync,
        Func<Task<int>> loadLocalAsync,
        string successSuffix,
        Action onSuccess)
    {
        try
        {
            WriteLine(progressMessage);
            var count = await updateAsync();
            onSuccess();
            return $"{label}: {count:N0} {successSuffix} ready";
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or IOException)
        {
            var count = await loadLocalAsync();
            onSuccess();
            return count > 0
                ? $"{label}: {count:N0} local {successSuffix} ready (online update failed)"
                : $"{label}: update failed (no local cache)";
        }
        catch (Exception ex)
        {
            return $"{label}: update failed ({ex.Message})";
        }
    }

    public static bool ShouldSkip(string[] args) =>
        IsHelpOrVersion(args) || ShouldSkipThreatIntel(args);

    public static bool IsHelpOrVersion(string[] args) =>
        args.Any(static a => a is "-h" or "-?" or "--help" or "--version" or "/?");

    public static bool ShouldSkipThreatIntel(string[] args) =>
        args.Any(static a => a is "--skip-bootstrap" or "--no-bootstrap");

    private static void WriteProgress(string message)
    {
        if (string.IsNullOrWhiteSpace(message))
        {
            return;
        }

        WriteLine($"  {message}");
    }

    private static void WriteResult(string message)
    {
        if (ConsoleLaunch.IsInteractive)
        {
            AnsiConsole.MarkupLine($"[green]{Markup.Escape(message)}[/]");
        }
        else
        {
            WriteLine(message);
        }
    }

    private static void WriteLine(string text)
    {
        try
        {
            Console.Out.WriteLine(text);
            Console.Out.Flush();
        }
        catch
        {
            // Ignore console write failures in redirected environments.
        }
    }
}
