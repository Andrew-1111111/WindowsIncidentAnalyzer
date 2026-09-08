using System.CommandLine;
using Microsoft.Extensions.DependencyInjection;
using Spectre.Console;
using WindowsIncidentAnalyzer.Infrastructure;
using WindowsIncidentAnalyzer.Models;
using WindowsIncidentAnalyzer.Repositories;
using WindowsIncidentAnalyzer.Services;

namespace WindowsIncidentAnalyzer.Commands;

public static class CveCommand
{
    public static Command Create(IServiceProvider services)
    {
        var command = new Command("cve", "Load, update, and scan the CVE database (CISA KEV catalog).");

        var loadPath = new Argument<string>("path")
        {
            Description = "Path to known_exploited_vulnerabilities.json."
        };
        var load = new Command("load", "Load CVE records from a local CISA KEV JSON file.");
        load.Arguments.Add(loadPath);
        load.SetAction(async (parse, ct) =>
        {
            var handler = services.GetRequiredService<CliErrorHandler>();
            return await handler.RunAsync(async token =>
            {
                var path = parse.GetValue(loadPath) ?? throw new ArgumentException("CVE database path is required.");
                var count = await services.GetRequiredService<ICveDatabaseService>().LoadFromFileAsync(path, token);
                AnsiConsole.MarkupLine($"[green]Loaded {count:N0} CVE record(s)[/] from {Markup.Escape(Path.GetFullPath(path))}.");
            }, ct);
        });

        var update = new Command("update", "Download the CISA Known Exploited Vulnerabilities catalog.");
        update.SetAction(async (parse, ct) =>
        {
            var handler = services.GetRequiredService<CliErrorHandler>();
            return await handler.RunAsync(async token =>
            {
                var count = await services.GetRequiredService<ICveDatabaseService>().UpdateFromCisaKevAsync(token);
                AnsiConsole.MarkupLine($"[green]Loaded {count:N0} CVE record(s)[/] from CISA KEV.");
            }, ct);
        });

        var lookupId = new Argument<string>("id")
        {
            Description = "CVE identifier (CVE-2024-1234)."
        };
        var lookup = new Command("lookup", "Look up a CVE record.");
        lookup.Arguments.Add(lookupId);
        lookup.SetAction(async (parse, ct) =>
        {
            var handler = services.GetRequiredService<CliErrorHandler>();
            return await handler.RunAsync(async token =>
            {
                var id = parse.GetValue(lookupId) ?? throw new ArgumentException("CVE ID is required.");
                var records = await services.GetRequiredService<ICveRepository>().GetAllAsync(token);
                var record = records.FirstOrDefault(r => r.CveId.Equals(id.Trim(), StringComparison.OrdinalIgnoreCase));
                if (record == null)
                {
                    AnsiConsole.MarkupLine("[yellow]CVE not found in the local database. Run 'cve update'.[/]");
                    return;
                }

                PrintRecord(record);
            }, ct);
        });

        var scan = new Command("scan", "Scan collected events for references to known exploited CVEs.");
        scan.SetAction(async (parse, ct) =>
        {
            var handler = services.GetRequiredService<CliErrorHandler>();
            return await handler.RunAsync(async token =>
            {
                var matches = await services.GetRequiredService<ICveDetectionService>().ScanAsync(null, token);
                if (matches.Count == 0)
                {
                    AnsiConsole.MarkupLine("[yellow]No CVE matches. Update the CVE database and collect events first.[/]");
                    return;
                }

                ConsolePresenter.CveMatches(matches);
            }, ct);
        });

        var stats = new Command("stats", "Show CVE database statistics.");
        stats.SetAction(async (parse, ct) =>
        {
            var handler = services.GetRequiredService<CliErrorHandler>();
            return await handler.RunAsync(async token =>
            {
                var cve = services.GetRequiredService<ICveDatabaseService>();
                await cve.EnsureLoadedAsync(token);
                if (cve.Count == 0)
                {
                    AnsiConsole.MarkupLine("[yellow]No CVE data loaded. Run 'cve update'.[/]");
                    return;
                }

                AnsiConsole.MarkupLine($"[bold]CVE catalog loaded:[/] {cve.Count:N0} record(s)");
                AnsiConsole.MarkupLine($"Cache: {Markup.Escape(Path.Combine(AppPaths.DataDirectory, "cve", "known_exploited_vulnerabilities.json"))}");
            }, ct);
        });

        command.Subcommands.Add(load);
        command.Subcommands.Add(update);
        command.Subcommands.Add(lookup);
        command.Subcommands.Add(scan);
        command.Subcommands.Add(stats);
        return command;
    }

    private static void PrintRecord(CveRecord record)
    {
        AnsiConsole.MarkupLine($"[bold]{Markup.Escape(record.CveId)}[/] {Markup.Escape(record.VulnerabilityName ?? "-")}");
        AnsiConsole.MarkupLine($"Vendor/Product: {Markup.Escape($"{record.VendorProject} / {record.Product}")}");
        if (!string.IsNullOrWhiteSpace(record.ShortDescription))
        {
            AnsiConsole.MarkupLine(Markup.Escape(record.ShortDescription));
        }

        if (!string.IsNullOrWhiteSpace(record.KnownRansomwareUse))
        {
            AnsiConsole.MarkupLine($"Ransomware use: {Markup.Escape(record.KnownRansomwareUse)}");
        }
    }
}
