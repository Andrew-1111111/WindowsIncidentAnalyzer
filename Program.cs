using Microsoft.Extensions.Hosting;
using Spectre.Console;
using WindowsIncidentAnalyzer.Commands;
using WindowsIncidentAnalyzer.Infrastructure;

namespace WindowsIncidentAnalyzer;

public static class Program
{
    public static async Task<int> Main(string[] args)
    {
        EnsureConsoleVisible();
        ConsoleCulture.UseEnglish();
        ConsoleIcon.Apply();

        var cliArgs = ProcessElevation.EnsurePrivileges(args);
        SingleInstanceGuard.AcquireOrOfferChoice();

        var exitCode = 1;

        try
        {
            using var host = CreateHost();

            await ApplicationBootstrap.RunAsync(
                host.Services,
                cliArgs,
                CancellationToken.None);

            var root = RootCommandFactory.Create(host.Services);

            if (cliArgs.Length == 0 && ConsoleLaunch.IsInteractive)
            {
                exitCode = await RunInteractiveAsync(root);
            }
            else
            {
                WritePrivilegeBanner();
                exitCode = await root.Parse(cliArgs).InvokeAsync();
            }
        }
        catch (Exception ex)
        {
            try
            {
                AnsiConsole.MarkupLine(
                    $"[red]Fatal error:[/] {Markup.Escape(ex.Message)}");

                AnsiConsole.WriteException(
                    ex,
                    ExceptionFormats.ShortenEverything);
            }
            catch
            {
                Console.Error.WriteLine(ex);
            }

            exitCode = 1;
        }
        finally
        {
            SingleInstanceGuard.Release();
        }

        if (cliArgs.Length != 0 || !ConsoleLaunch.IsInteractive)
        {
            ConsoleLaunch.PauseIfNeeded();
        }

        return exitCode;
    }

    private static void EnsureConsoleVisible()
    {
        try
        {
            Console.Title = "Windows Incident Analyzer";
        }
        catch
        {
            // Console may be unavailable in some host environments.
        }
    }

    private static void WritePrivilegeBanner()
    {
        if (ProcessElevation.IsAdministrator())
        {
            AnsiConsole.MarkupLine(
                "[green]Administrator:[/] full access to the Security and Sysmon logs.");

            return;
        }

        if (AppRuntime.LimitedMode)
        {
            AnsiConsole.MarkupLine(
                "[yellow]Not running as Administrator. Limited mode is active.[/]");

            AnsiConsole.MarkupLine(
                "[grey]The Security log (and often Sysmon) cannot be read. " +
                "Application, System, PowerShell, EVTX files, search, analyze, " +
                "timeline, IOC, and export still work.[/]");

            AnsiConsole.WriteLine();
        }
    }

    private static async Task<int> RunInteractiveAsync(
        System.CommandLine.RootCommand root)
    {
        AnsiConsole.Write(
            new FigletText("WIA").Color(Color.Cyan1));

        AnsiConsole.MarkupLine(
            "[bold]Windows Incident Analyzer[/] — defensive DFIR console");

        WritePrivilegeBanner();

        AnsiConsole.MarkupLine(
            "[grey]Type a command (collect, analyze, timeline, search, stats, " +
            "ioc, sigma, export) or [white]help[/] / [white]exit[/].[/]");

        AnsiConsole.WriteLine();

        var last = 0;

        while (true)
        {
            string? line;

            try
            {
                line = AnsiConsole
                    .Prompt(
                        new TextPrompt<string>("[cyan]wia>[/]")
                            .AllowEmpty());
            }
            catch (Exception)
            {
                break;
            }

            if (string.IsNullOrWhiteSpace(line))
            {
                continue;
            }

            var trimmed = line.Trim();

            if (trimmed.Equals(
                    "exit",
                    StringComparison.OrdinalIgnoreCase) ||
                trimmed.Equals(
                    "quit",
                    StringComparison.OrdinalIgnoreCase) ||
                trimmed.Equals(
                    "q",
                    StringComparison.OrdinalIgnoreCase))
            {
                break;
            }

            if (trimmed.Equals(
                    "help",
                    StringComparison.OrdinalIgnoreCase) ||
                trimmed is "-h" or "--help" or "?")
            {
                trimmed = "--help";
            }

            try
            {
                last = await root
                    .Parse(trimmed)
                    .InvokeAsync();
            }
            catch (Exception ex)
            {
                AnsiConsole.MarkupLine(
                    $"[red]{Markup.Escape(ex.Message)}[/]");

                last = 1;
            }
        }

        return last;
    }

    private static IHost CreateHost()
    {
        var builder = Host.CreateApplicationBuilder(
            new HostApplicationBuilderSettings
            {
                Args = [],
                ContentRootPath = AppPaths.ExecutableDirectory
            });

        LoggingConfiguration.Configure(builder);
        ConfigurationLoader.Configure(builder);

        builder.Services.AddApplicationServices(
            builder.Configuration);

        return builder.Build();
    }
}