using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Spectre.Console;
using WindowsIncidentAnalyzer.Configuration;
using WindowsIncidentAnalyzer.Repositories;
using WindowsIncidentAnalyzer.Services;

namespace WindowsIncidentAnalyzer.Infrastructure;

public static class ApplicationBootstrap
{
    public static async Task RunAsync(IServiceProvider services, string[] args, CancellationToken cancellationToken)
    {
        if (ShouldSkip(args))
        {
            return;
        }

        var startup = services.GetRequiredService<IOptions<AnalyzerOptions>>().Value.Startup;
        if (!startup.AutoUpdateIocFeeds && !startup.AutoUpdateSigmaRules)
        {
            return;
        }

        var cache = StartupCache.Load();
        var iocNeeded = startup.AutoUpdateIocFeeds && cache.ShouldRefreshIoc(startup.IocRefreshHours);
        var sigmaNeeded = startup.AutoUpdateSigmaRules && cache.ShouldRefreshSigma(startup.SigmaRefreshHours);

        if (!iocNeeded && !sigmaNeeded)
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

            if (!iocNeeded && !sigmaNeeded)
            {
                WriteLine($"Threat intelligence ready: {status.IocCount:N0} IOC(s), {status.SigmaRuleCount:N0} Sigma rule(s) - cached.");
                WriteLine(
                    $"Next online update: IOC after {FormatNextRefresh(cache.IocUpdatedUtc, startup.IocRefreshHours)}, " +
                    $"Sigma after {FormatNextRefresh(cache.SigmaUpdatedUtc, startup.SigmaRefreshHours)}.");
                return;
            }
        }

        WriteLine(iocNeeded || sigmaNeeded
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

        foreach (var result in await Task.WhenAll(tasks))
        {
            WriteResult(result);
        }

        var finalStatus = await EnsureLocalThreatIntelAsync(services, cancellationToken);
        WriteLine($"Ready: {finalStatus.IocCount:N0} IOC(s), {finalStatus.SigmaRuleCount:N0} Sigma rule(s).");

        cache.Save();
        WriteLine(string.Empty);
    }

    private static async Task<ThreatIntelStatus> EnsureLocalThreatIntelAsync(
        IServiceProvider services,
        CancellationToken cancellationToken)
    {
        var sigma = services.GetRequiredService<ISigmaRuleService>();
        await sigma.EnsureLoadedAsync(cancellationToken);

        var iocRepo = services.GetRequiredService<IIocRepository>();
        var iocCount = (await iocRepo.GetAllAsync(cancellationToken)).Count;
        var sigmaCount = sigma.GetRules().Count;

        return new ThreatIntelStatus(iocCount, sigmaCount);
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

    private readonly record struct ThreatIntelStatus(int IocCount, int SigmaRuleCount);

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
            WriteLine("Sigma: downloading rules from SigmaHQ...");
            var sigma = services.GetRequiredService<ISigmaRuleService>();
            var count = await sigma.UpdateFromSigmaHqAsync(cancellationToken);
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

    public static bool ShouldSkip(string[] args)
    {
        if (args.Any(static a => a is "--skip-bootstrap" or "--no-bootstrap"))
        {
            return true;
        }

        return args.Any(static a => a is "-h" or "-?" or "--help" or "--version" or "/?");
    }

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
