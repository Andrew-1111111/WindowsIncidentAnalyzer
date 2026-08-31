using System.Diagnostics;
using Spectre.Console;

namespace WindowsIncidentAnalyzer.Infrastructure;

internal static class SingleInstanceGuard
{
    private const string MutexName = @"Local\WindowsIncidentAnalyzer.wia.SingleInstance";
    private static Mutex? _mutex;
    private static bool _ownsMutex;

    public static void AcquireOrOfferChoice()
    {
        _mutex = new Mutex(initiallyOwned: true, MutexName, out var createdNew);
        if (createdNew)
        {
            _ownsMutex = true;
            return;
        }

        if (!ConsoleLaunch.IsInteractive)
        {
            Console.Error.WriteLine("Windows Incident Analyzer is already running.");
            Environment.Exit(2);
        }

        AnsiConsole.MarkupLine("[yellow]Windows Incident Analyzer is already running.[/] A second copy was started.");
        AnsiConsole.WriteLine();
        AnsiConsole.MarkupLine("  [bold]1)[/] Close the existing instance");
        AnsiConsole.MarkupLine("  [bold]2)[/] Exit");
        AnsiConsole.WriteLine();

        var choice = AnsiConsole.Prompt(
            new TextPrompt<string>("Choose an action [1/2]:")
                .Validate(value => value is "1" or "2"
                    ? ValidationResult.Success()
                    : ValidationResult.Error("Enter 1 or 2."))
                .DefaultValue("2"));

        if (choice == "2")
        {
            Release();
            Environment.Exit(0);
        }

        if (!CloseOtherInstances())
        {
            AnsiConsole.MarkupLine("[red]Could not close the existing instance.[/] Close it manually, or run this window as Administrator.");
            ConsoleLaunch.PauseIfNeeded();
            Release();
            Environment.Exit(1);
        }

        try
        {
            if (_mutex.WaitOne(TimeSpan.FromSeconds(8)))
            {
                _ownsMutex = true;
                return;
            }

            AnsiConsole.MarkupLine("[red]The previous instance is still holding the lock.[/]");
            ConsoleLaunch.PauseIfNeeded();
            Release();
            Environment.Exit(1);
        }
        catch (AbandonedMutexException)
        {
            _ownsMutex = true;
        }
    }

    public static void Release()
    {
        if (_mutex is null)
        {
            return;
        }

        try
        {
            if (_ownsMutex)
            {
                _mutex.ReleaseMutex();
            }
        }
        catch (ApplicationException)
        {
        }

        _ownsMutex = false;
        _mutex.Dispose();
        _mutex = null;
    }

    private static bool CloseOtherInstances()
    {
        var current = Process.GetCurrentProcess();
        var currentPath = Environment.ProcessPath;
        var closed = 0;

        foreach (var process in Process.GetProcesses())
        {
            try
            {
                if (process.Id == current.Id)
                {
                    continue;
                }

                var sameName = string.Equals(process.ProcessName, current.ProcessName, StringComparison.OrdinalIgnoreCase)
                               || string.Equals(process.ProcessName, "wia", StringComparison.OrdinalIgnoreCase);
                var samePath = false;
                try
                {
                    samePath = !string.IsNullOrEmpty(currentPath)
                               && string.Equals(process.MainModule?.FileName, currentPath, StringComparison.OrdinalIgnoreCase);
                }
                catch
                {
                    samePath = false;
                }

                if (!sameName && !samePath)
                {
                    continue;
                }

                AnsiConsole.MarkupLine($"[grey]Closing process PID {process.Id}...[/]");
                try
                {
                    process.Kill(entireProcessTree: true);
                    process.WaitForExit(8000);
                    closed++;
                }
                catch (Exception ex)
                {
                    AnsiConsole.MarkupLine($"[red]PID {process.Id}:[/] {Markup.Escape(ex.Message)}");
                    return false;
                }
            }
            finally
            {
                process.Dispose();
            }
        }

        return true;
    }
}
