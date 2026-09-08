using System.CommandLine;
using Microsoft.Extensions.DependencyInjection;
using Spectre.Console;
using WindowsIncidentAnalyzer.Infrastructure;
using WindowsIncidentAnalyzer.Repositories;
using WindowsIncidentAnalyzer.Services;

namespace WindowsIncidentAnalyzer.Commands;

public static class MitreCommand
{
    public static Command Create(IServiceProvider services)
    {
        var command = new Command("mitre", "Load, update, and inspect the MITRE ATT&CK enterprise database.");

        var loadPath = new Argument<string>("path")
        {
            Description = "Path to enterprise-attack.json (STIX bundle from mitre/cti)."
        };
        var load = new Command("load", "Load MITRE ATT&CK data from a local JSON file.");
        load.Arguments.Add(loadPath);
        load.SetAction(async (parse, ct) =>
        {
            var handler = services.GetRequiredService<CliErrorHandler>();
            return await handler.RunAsync(async token =>
            {
                var path = parse.GetValue(loadPath) ?? throw new ArgumentException("MITRE database path is required.");
                var count = await services.GetRequiredService<IMitreAttackService>().LoadFromFileAsync(path, token);
                AnsiConsole.MarkupLine($"[green]Loaded {count:N0} MITRE technique(s)[/] from {Markup.Escape(Path.GetFullPath(path))}.");
            }, ct);
        });

        var update = new Command("update", "Download MITRE ATT&CK enterprise bundle from mitre/cti.");
        update.SetAction(async (parse, ct) =>
        {
            var handler = services.GetRequiredService<CliErrorHandler>();
            return await handler.RunAsync(async token =>
            {
                var count = await services.GetRequiredService<IMitreAttackService>().UpdateFromMitreCtiAsync(token);
                AnsiConsole.MarkupLine($"[green]Loaded {count:N0} MITRE technique(s)[/] from mitre/cti.");
            }, ct);
        });

        var lookupId = new Argument<string>("id")
        {
            Description = "Technique ID or Sigma tag (T1033 or attack.t1033)."
        };
        var lookup = new Command("lookup", "Look up a MITRE ATT&CK technique or tactic.");
        lookup.Arguments.Add(lookupId);
        lookup.SetAction(async (parse, ct) =>
        {
            var handler = services.GetRequiredService<CliErrorHandler>();
            return await handler.RunAsync(async token =>
            {
                var id = parse.GetValue(lookupId) ?? throw new ArgumentException("MITRE ID is required.");
                var mitre = services.GetRequiredService<IMitreAttackService>();
                await mitre.EnsureLoadedAsync(token);

                if (mitre.TryGetTechnique(id, out var technique))
                {
                    AnsiConsole.MarkupLine($"[bold]{Markup.Escape(technique.ExternalId)}[/] {Markup.Escape(technique.Name)}");
                    if (!string.IsNullOrWhiteSpace(technique.Url))
                    {
                        AnsiConsole.MarkupLine($"[grey]{Markup.Escape(technique.Url)}[/]");
                    }

                    if (technique.TacticShortNames.Count > 0)
                    {
                        var tactics = string.Join(", ", technique.TacticShortNames.Select(t => mitre.TryGetTactic(t, out var tactic) ? tactic.Name : t));
                        AnsiConsole.MarkupLine($"Tactics: {Markup.Escape(tactics)}");
                    }

                    return;
                }

                if (mitre.TryGetTactic(id, out var tacticInfo))
                {
                    AnsiConsole.MarkupLine($"[bold]{Markup.Escape(tacticInfo.ShortName)}[/] {Markup.Escape(tacticInfo.Name)}");
                    if (!string.IsNullOrWhiteSpace(tacticInfo.Url))
                    {
                        AnsiConsole.MarkupLine($"[grey]{Markup.Escape(tacticInfo.Url)}[/]");
                    }

                    return;
                }

                AnsiConsole.MarkupLine("[yellow]No MITRE ATT&CK entry found. Run 'mitre update' first.[/]");
            }, ct);
        });

        var stats = new Command("stats", "Show MITRE ATT&CK database statistics.");
        stats.SetAction(async (parse, ct) =>
        {
            var handler = services.GetRequiredService<CliErrorHandler>();
            return await handler.RunAsync(async token =>
            {
                var mitre = services.GetRequiredService<IMitreAttackService>();
                await mitre.EnsureLoadedAsync(token);
                var techniques = mitre.GetTechniques();
                var tactics = mitre.GetTactics();
                if (techniques.Count == 0)
                {
                    AnsiConsole.MarkupLine("[yellow]No MITRE ATT&CK data loaded. Run 'mitre update'.[/]");
                    return;
                }

                AnsiConsole.MarkupLine($"[bold]MITRE ATT&CK loaded:[/] {techniques.Count:N0} technique(s), {tactics.Count:N0} tactic(s)");
                AnsiConsole.MarkupLine($"Cache: {Markup.Escape(Path.Combine(AppPaths.DataDirectory, "mitre", "enterprise-attack.json"))}");
            }, ct);
        });

        command.Subcommands.Add(load);
        command.Subcommands.Add(update);
        command.Subcommands.Add(lookup);
        command.Subcommands.Add(stats);
        return command;
    }
}
