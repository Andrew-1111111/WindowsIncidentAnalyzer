using System.CommandLine;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Spectre.Console;
using WindowsIncidentAnalyzer.Configuration;
using WindowsIncidentAnalyzer.Infrastructure;
using WindowsIncidentAnalyzer.Services;

namespace WindowsIncidentAnalyzer.Commands;

public static class ExportCommand
{
    public static Command Create(IServiceProvider services)
    {
        var command = new Command("export", "Export findings, IOC matches, correlations, and timeline.");
        SharedCliOptions.Format.DefaultValueFactory = _ => "html";
        command.Options.Add(SharedCliOptions.Format);
        var output = new Option<string?>("--output")
        {
            Description = "Output file path. CSV export writes Excel (.xlsx) files: findings, timeline, IOCs, correlations, events, statistics."
        };
        command.Options.Add(output);
        command.Options.Add(SharedCliOptions.Hours);
        command.Options.Add(SharedCliOptions.From);
        command.Options.Add(SharedCliOptions.To);
        command.Options.Add(SharedCliOptions.Date);
        command.Options.Add(SharedCliOptions.Limit);

        command.SetAction(async (parse, ct) =>
        {
            var handler = services.GetRequiredService<CliErrorHandler>();
            return await handler.RunAsync(async token =>
            {
                var analyzer = services.GetRequiredService<IOptions<AnalyzerOptions>>().Value;
                var filter = SharedCliOptions.BuildFilter(parse, analyzer, defaultHoursWhenMissing: false);
                var format = parse.GetValue(SharedCliOptions.Format) ?? "html";
                var path = await services.GetRequiredService<IExportService>()
                    .ExportAsync(format, parse.GetValue(output), filter, token);
                AnsiConsole.MarkupLine($"[green]Export written to[/] {Markup.Escape(path)}");
            }, ct);
        });

        return command;
    }
}
