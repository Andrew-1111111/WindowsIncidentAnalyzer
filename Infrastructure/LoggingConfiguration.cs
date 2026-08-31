using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Console;

namespace WindowsIncidentAnalyzer.Infrastructure;

public static class LoggingConfiguration
{
    public static void Configure(HostApplicationBuilder builder)
    {
        builder.Logging.ClearProviders();
        builder.Logging.SetMinimumLevel(LogLevel.Information);

        // Do not write ILogger to stdout: Spectre.Console live status would share the same
        // line with SimpleConsole and produce unreadable concatenated output.
        var logDir = AppPaths.DataDirectory;
        try
        {
            Directory.CreateDirectory(logDir);
            builder.Logging.AddProvider(new FileLoggerProvider(Path.Combine(logDir, "wia.log")));
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"File logging disabled: {ex.Message}");
            builder.Logging.AddSimpleConsole(options =>
            {
                options.TimestampFormat = "HH:mm:ss ";
                options.SingleLine = true;
                options.ColorBehavior = LoggerColorBehavior.Disabled;
            });
            builder.Logging.AddFilter("Microsoft.Extensions.Logging.Console.ConsoleLoggerProvider", LogLevel.Error);
        }
    }
}

internal sealed class FileLoggerProvider : ILoggerProvider
{
    private readonly StreamWriter _writer;
    private readonly object _sync = new();

    public FileLoggerProvider(string path)
    {
        var stream = new FileStream(path, FileMode.Append, FileAccess.Write, FileShare.ReadWrite);
        _writer = new StreamWriter(stream) { AutoFlush = true };
    }

    public ILogger CreateLogger(string categoryName) => new FileLogger(categoryName, _writer, _sync);

    public void Dispose() => _writer.Dispose();
}

internal sealed class FileLogger : ILogger
{
    private readonly string _category;
    private readonly StreamWriter _writer;
    private readonly object _sync;

    public FileLogger(string category, StreamWriter writer, object sync)
    {
        _category = category;
        _writer = writer;
        _sync = sync;
    }

    public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

    public bool IsEnabled(LogLevel logLevel) => logLevel != LogLevel.None;

    public void Log<TState>(
        LogLevel logLevel,
        EventId eventId,
        TState state,
        Exception? exception,
        Func<TState, Exception?, string> formatter)
    {
        if (!IsEnabled(logLevel))
        {
            return;
        }

        var line = $"{DateTime.UtcNow:O} [{logLevel}] {_category}: {formatter(state, exception)}";
        if (exception != null)
        {
            line += Environment.NewLine + exception;
        }

        lock (_sync)
        {
            _writer.WriteLine(line);
        }
    }
}
