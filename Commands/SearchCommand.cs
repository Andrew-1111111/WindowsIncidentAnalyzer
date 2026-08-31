using System.CommandLine;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Spectre.Console;
using WindowsIncidentAnalyzer.Configuration;
using WindowsIncidentAnalyzer.Infrastructure;
using WindowsIncidentAnalyzer.Repositories;
using WindowsIncidentAnalyzer.Services;

namespace WindowsIncidentAnalyzer.Commands;

public static class SearchCommand
{
    public static Command Create(IServiceProvider services)
    {
        var command = new Command("search", "Search collected events by Event ID, user, IP, process, keyword, and time range.");
        command.Options.Add(SharedCliOptions.EventId);
        command.Options.Add(SharedCliOptions.User);
        command.Options.Add(SharedCliOptions.Ip);
        command.Options.Add(SharedCliOptions.Process);
        command.Options.Add(SharedCliOptions.Keyword);
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
                var rows = await services.GetRequiredService<IEventRepository>().QueryAsync(filter, token);
                if (rows.Count == 0)
                {
                    AnsiConsole.MarkupLine("[yellow]No events matched the filter. Collect logs first with 'wia collect'.[/]");
                    return;
                }

                ConsolePresenter.Events(rows);
            }, ct);
        });

        return command;
    }
}
