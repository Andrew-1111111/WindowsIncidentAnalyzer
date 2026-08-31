using System.CommandLine;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Spectre.Console;
using WindowsIncidentAnalyzer.Configuration;
using WindowsIncidentAnalyzer.Infrastructure;
using WindowsIncidentAnalyzer.Services;

namespace WindowsIncidentAnalyzer.Commands;

public static class TimelineCommand
{
    public static Command Create(IServiceProvider services)
    {
        var command = new Command("timeline", "Build a chronological investigation timeline.");
        command.Options.Add(SharedCliOptions.Hours);
        command.Options.Add(SharedCliOptions.From);
        command.Options.Add(SharedCliOptions.To);
        command.Options.Add(SharedCliOptions.Date);
        command.Options.Add(SharedCliOptions.User);
        command.Options.Add(SharedCliOptions.Ip);
        command.Options.Add(SharedCliOptions.Process);
        command.Options.Add(SharedCliOptions.EventId);
        command.Options.Add(SharedCliOptions.Limit);
        command.Options.Add(SharedCliOptions.Export);

        command.SetAction(async (parse, ct) =>
        {
            var handler = services.GetRequiredService<CliErrorHandler>();
            return await handler.RunAsync(async token =>
            {
                var analyzer = services.GetRequiredService<IOptions<AnalyzerOptions>>().Value;
                var filter = SharedCliOptions.BuildFilter(parse, analyzer, defaultHoursWhenMissing: true);
                var items = await services.GetRequiredService<ITimelineService>().BuildAsync(filter, token);
                if (items.Count == 0)
                {
                    AnsiConsole.MarkupLine("[yellow]Timeline is empty. Collect events first.[/]");
                    return;
                }

                ConsolePresenter.Timeline(items);

                var export = parse.GetValue(SharedCliOptions.Export);
                if (!string.IsNullOrWhiteSpace(export))
                {
                    var format = Path.GetExtension(export).TrimStart('.').ToLowerInvariant();
                    if (string.IsNullOrEmpty(format))
                    {
                        format = "csv";
                    }

                    var path = await services.GetRequiredService<IExportService>().ExportAsync(format, export, filter, token);
                    AnsiConsole.MarkupLine($"[green]Exported timeline package to[/] {Markup.Escape(path)}");
                }
            }, ct);
        });

        return command;
    }
}
