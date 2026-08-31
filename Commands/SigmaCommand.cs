using System.CommandLine;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Spectre.Console;
using WindowsIncidentAnalyzer.Configuration;
using WindowsIncidentAnalyzer.Infrastructure;
using WindowsIncidentAnalyzer.Services;

namespace WindowsIncidentAnalyzer.Commands;

public static class SigmaCommand
{
    public static Command Create(IServiceProvider services)
    {
        var command = new Command("sigma", "Load, update, and inspect Sigma detection rules.");

        var loadPath = new Argument<string>("path")
        {
            Description = "Directory containing Sigma YAML rules."
        };
        var load = new Command("load", "Load Sigma rules from a local directory.");
        load.Arguments.Add(loadPath);
        load.SetAction(async (parse, ct) =>
        {
            var handler = services.GetRequiredService<CliErrorHandler>();
            return await handler.RunAsync(async token =>
            {
                var path = parse.GetValue(loadPath) ?? throw new ArgumentException("Sigma rules path is required.");
                var count = await services.GetRequiredService<ISigmaRuleService>().LoadFromDirectoryAsync(path, token);
                AnsiConsole.MarkupLine($"[green]Loaded {count:N0} Sigma rule(s)[/] from {Markup.Escape(Path.GetFullPath(path))}.");
            }, ct);
        });

        var update = new Command("update", "Download SigmaHQ Windows rules and load them.");
        update.SetAction(async (parse, ct) =>
        {
            var handler = services.GetRequiredService<CliErrorHandler>();
            return await handler.RunAsync(async token =>
            {
                var count = await services.GetRequiredService<ISigmaRuleService>().UpdateFromSigmaHqAsync(token);
                AnsiConsole.MarkupLine($"[green]Loaded {count:N0} Sigma rule(s)[/] from SigmaHQ.");
            }, ct);
        });

        var list = new Command("list", "List loaded Sigma rules.");
        var limit = new Option<int?>("--limit") { Description = "Maximum number of rules to display." };
        list.Options.Add(limit);
        list.SetAction(async (parse, ct) =>
        {
            var handler = services.GetRequiredService<CliErrorHandler>();
            return await handler.RunAsync(async token =>
            {
                var sigma = services.GetRequiredService<ISigmaRuleService>();
                await sigma.EnsureLoadedAsync(token);
                var rules = sigma.GetRules();
                if (rules.Count == 0)
                {
                    AnsiConsole.MarkupLine("[yellow]No Sigma rules loaded. Run 'sigma load <path>' or 'sigma update'.[/]");
                    return;
                }

                var max = parse.GetValue(limit) ?? 50;
                var table = new Table().Border(TableBorder.Rounded);
                table.AddColumn("Severity");
                table.AddColumn("Title");
                table.AddColumn("Category");
                table.AddColumn("Id");
                foreach (var rule in rules.Take(max))
                {
                    table.AddRow(
                        rule.Severity.ToString(),
                        Markup.Escape(rule.Title),
                        Markup.Escape(rule.Logsource.Category ?? "-"),
                        Markup.Escape(rule.Id ?? "-"));
                }

                AnsiConsole.Write(table);
                if (rules.Count > max)
                {
                    AnsiConsole.MarkupLine($"[grey]Showing {max} of {rules.Count:N0} rule(s).[/]");
                }
            }, ct);
        });

        var stats = new Command("stats", "Show summary statistics for loaded Sigma rules.");
        stats.SetAction(async (parse, ct) =>
        {
            var handler = services.GetRequiredService<CliErrorHandler>();
            return await handler.RunAsync(async token =>
            {
                var sigma = services.GetRequiredService<ISigmaRuleService>();
                await sigma.EnsureLoadedAsync(token);
                var rules = sigma.GetRules();
                if (rules.Count == 0)
                {
                    AnsiConsole.MarkupLine("[yellow]No Sigma rules loaded.[/]");
                    return;
                }

                var options = services.GetRequiredService<IOptions<DetectionRulesOptions>>().Value.SigmaRules;
                AnsiConsole.MarkupLine($"[bold]Sigma rules loaded:[/] {rules.Count:N0}");
                AnsiConsole.MarkupLine($"Rules path: {Markup.Escape(AppPaths.ResolveRelative(options.RulesPath))}");
                foreach (var group in rules.GroupBy(r => r.Severity).OrderByDescending(g => g.Key))
                {
                    AnsiConsole.MarkupLine($"  {group.Key}: {group.Count():N0}");
                }
            }, ct);
        });

        command.Subcommands.Add(load);
        command.Subcommands.Add(update);
        command.Subcommands.Add(list);
        command.Subcommands.Add(stats);
        return command;
    }
}
