using System.Diagnostics.Eventing.Reader;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Logging;
using Spectre.Console;

namespace WindowsIncidentAnalyzer.Infrastructure;

public sealed class CliErrorHandler(ILogger<CliErrorHandler> logger)
{
    public async Task<int> RunAsync(Func<CancellationToken, Task> action, CancellationToken cancellationToken)
    {
        try
        {
            await action(cancellationToken);
            return 0;
        }
        catch (OperationCanceledException)
        {
            AnsiConsole.MarkupLine("[yellow]Operation cancelled.[/]");
            return 130;
        }
        catch (UnauthorizedAccessException ex)
        {
            logger.LogError(ex, "Access denied");
            AnsiConsole.MarkupLine($"[red]Access denied.[/] {Markup.Escape(ex.Message)}");
            AnsiConsole.MarkupLine("[grey]Administrator is only required for live Security (and often Sysmon) logs. search / analyze / EVTX import work without elevation. Use: collect --log Application[/]");
            return 5;
        }
        catch (EventLogNotFoundException ex)
        {
            logger.LogWarning(ex, "Event log not found");
            AnsiConsole.MarkupLine($"[yellow]Event log not found.[/] {Markup.Escape(ex.Message)}");
            AnsiConsole.MarkupLine("[grey]Sysmon and PowerShell operational logs are only available when those components are installed.[/]");
            return 2;
        }
        catch (EventLogException ex)
        {
            logger.LogError(ex, "Event log error");
            AnsiConsole.MarkupLine($"[red]Event log error.[/] {Markup.Escape(ex.Message)}");
            AnsiConsole.MarkupLine("[grey]The EVTX file may be incomplete or the channel may be unavailable.[/]");
            return 3;
        }
        catch (SqliteException ex)
        {
            logger.LogError(ex, "SQLite error");
            AnsiConsole.MarkupLine($"[red]Database error.[/] {Markup.Escape(ex.Message)}");
            return 4;
        }
        catch (InvalidOperationException ex)
        {
            logger.LogError(ex, "Invalid operation");
            AnsiConsole.MarkupLine($"[red]{Markup.Escape(ex.Message)}[/]");
            return 1;
        }
        catch (ArgumentException ex)
        {
            logger.LogWarning(ex, "Invalid argument");
            AnsiConsole.MarkupLine($"[yellow]Invalid argument:[/] {Markup.Escape(ex.Message)}");
            return 1;
        }
        catch (IOException ex)
        {
            logger.LogError(ex, "I/O error");
            AnsiConsole.MarkupLine($"[red]I/O error.[/] {Markup.Escape(ex.Message)}");
            return 1;
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Unhandled error");
            AnsiConsole.MarkupLine($"[red]Unexpected error:[/] {Markup.Escape(ex.Message)}");
            return 1;
        }
    }
}
