using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using WindowsIncidentAnalyzer.Configuration;
using WindowsIncidentAnalyzer.Persistence;

namespace WindowsIncidentAnalyzer.Infrastructure;

/// <summary>
/// Resolves the investigation database path and ensures the EF Core schema exists.
/// </summary>
public sealed class InvestigationDatabase : IAsyncDisposable
{
    private readonly ILogger<InvestigationDatabase> _logger;
    private readonly IServiceProvider _services;
    private readonly SemaphoreSlim _initLock = new(1, 1);
    private readonly SqliteConnection? _keepAlive;
    private bool _initialized;

    public InvestigationDatabase(
        IOptions<AnalyzerOptions> options,
        ILogger<InvestigationDatabase> logger,
        IServiceProvider services)
    {
        _logger = logger;
        _services = services;
        var path = ConfigurationLoader.ResolveDatabasePath(options.Value);
        var directory = Path.GetDirectoryName(path);
        if (!string.IsNullOrWhiteSpace(directory))
        {
            Directory.CreateDirectory(directory);
        }

        DatabasePath = path;
        ConnectionString = new SqliteConnectionStringBuilder
        {
            DataSource = path,
            Mode = SqliteOpenMode.ReadWriteCreate,
            Cache = SqliteCacheMode.Shared
        }.ToString();

        if (string.Equals(path, ":memory:", StringComparison.OrdinalIgnoreCase))
        {
            _keepAlive = new SqliteConnection(ConnectionString);
            _keepAlive.Open();
        }
        else if (!File.Exists(path))
        {
            // EF Core Exists() opens the file ReadOnly first; a missing file throws
            // SqliteException (Error 14) that VS surfaces as a first-chance exception.
            // An empty placeholder avoids that probe failure.
            using var _ = File.Create(path);
        }
    }

    public string DatabasePath { get; }

    public string ConnectionString { get; }

    public async Task EnsureInitializedAsync(CancellationToken cancellationToken = default)
    {
        if (_initialized)
        {
            return;
        }

        await _initLock.WaitAsync(cancellationToken);
        try
        {
            if (_initialized)
            {
                return;
            }

            var factory = _services.GetRequiredService<IDbContextFactory<InvestigationDbContext>>();
            await using var db = await factory.CreateDbContextAsync(cancellationToken);
            await db.Database.EnsureCreatedAsync(cancellationToken);
            await InvestigationSchemaUpgrader.ApplyConnectionPragmasAsync(db, cancellationToken);
            await InvestigationSchemaUpgrader.EnsureCompatibleSchemaAsync(db, cancellationToken);
            _initialized = true;
            _logger.LogInformation("SQLite investigation database ready at {Path}", DatabasePath);
        }
        finally
        {
            _initLock.Release();
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (_keepAlive != null)
        {
            await _keepAlive.DisposeAsync();
        }

        _initLock.Dispose();
    }
}
