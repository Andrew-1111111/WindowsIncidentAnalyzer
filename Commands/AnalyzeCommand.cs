using System.CommandLine;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Spectre.Console;
using WindowsIncidentAnalyzer.Configuration;
using WindowsIncidentAnalyzer.Infrastructure;
using WindowsIncidentAnalyzer.Models;
using WindowsIncidentAnalyzer.Services;

namespace WindowsIncidentAnalyzer.Commands;

public static class AnalyzeCommand
{
    public static Command Create(IServiceProvider services)
    {
        var command = new Command("analyze", "Run detection rules, IOC matching, and correlation over collected events.");
        command.Options.Add(SharedCliOptions.Hours);
        command.Options.Add(SharedCliOptions.From);
        command.Options.Add(SharedCliOptions.To);
        command.Options.Add(SharedCliOptions.Date);
        command.Options.Add(SharedCliOptions.User);
        command.Options.Add(SharedCliOptions.Ip);
        command.Options.Add(SharedCliOptions.Limit);

        command.SetAction(async (parse, ct) =>
        {
            var handler = services.GetRequiredService<CliErrorHandler>();
            return await handler.RunAsync(async token =>
            {
                var analyzer = services.GetRequiredService<IOptions<AnalyzerOptions>>().Value;
                var filter = SharedCliOptions.BuildFilter(parse, analyzer, defaultHoursWhenMissing: false);
                if (parse.GetValue(SharedCliOptions.Limit) is null)
                {
                    filter = filter with { Limit = analyzer.Collection.DefaultLimit };
                }

                InvestigationSummary summary = default!;
                await AnsiConsole.Status()
                    .AutoRefresh(true)
                    .Spinner(Spinner.Known.Dots)
                    .StartAsync("Analyzing investigation data...", async _ =>
                    {
                        summary = await services.GetRequiredService<IInvestigationService>().AnalyzeAsync(filter, token);
                    });

                AnsiConsole.WriteLine();
                ConsolePresenter.AnalysisResults(summary);
            }, ct);
        });

        return command;
    }
}
