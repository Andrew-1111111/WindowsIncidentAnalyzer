using System.CommandLine;
using System.CommandLine.Help;
using Microsoft.Extensions.DependencyInjection;

namespace WindowsIncidentAnalyzer.Commands;

public static class RootCommandFactory
{
    public static RootCommand Create(IServiceProvider services)
    {
        var root = new RootCommand(
            "Windows Incident Analyzer — defensive DFIR / incident response tooling for Windows Event Logs.");
        foreach (var option in root.Options)
        {
            switch (option)
            {
                case HelpOption:
                    option.Description = "Show help and usage information.";
                    break;
                case VersionOption:
                    option.Description = "Show version information.";
                    break;
            }
        }

        root.Subcommands.Add(CollectCommand.Create(services));
        root.Subcommands.Add(SearchCommand.Create(services));
        root.Subcommands.Add(TimelineCommand.Create(services));
        root.Subcommands.Add(AnalyzeCommand.Create(services));
        root.Subcommands.Add(IocCommand.Create(services));
        root.Subcommands.Add(SigmaCommand.Create(services));
        root.Subcommands.Add(ExportCommand.Create(services));
        root.Subcommands.Add(StatsCommand.Create(services));
        return root;
    }
}
