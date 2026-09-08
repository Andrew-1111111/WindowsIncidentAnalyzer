using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using WindowsIncidentAnalyzer.Configuration;
using WindowsIncidentAnalyzer.Persistence;
using WindowsIncidentAnalyzer.Infrastructure;
using Xunit;

namespace WindowsIncidentAnalyzer.Tests.UnitTests;

public sealed class InvestigationDatabaseInitTests
{
    [Fact]
    public async Task EnsureInitialized_Twice_DoesNotThrow()
    {
        var path = Path.Combine(Path.GetTempPath(), $"wia-init-{Guid.NewGuid():N}.db");
        var firstChance = new List<string>();
        AppDomain.CurrentDomain.FirstChanceException += OnFirstChance;
        try
        {
            await using var harness = CreateHarness(path);
            await harness.Database.EnsureInitializedAsync();
            await harness.Database.EnsureInitializedAsync();

            await using var db = await harness.Factory.CreateDbContextAsync();
            Assert.True(await db.Database.CanConnectAsync());
            Assert.Empty(await db.Events.ToListAsync());
        }
        finally
        {
            AppDomain.CurrentDomain.FirstChanceException -= OnFirstChance;
            Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
            foreach (var leftover in new[] { path, path + "-wal", path + "-shm" })
            {
                try
                {
                    if (File.Exists(leftover))
                    {
                        File.Delete(leftover);
                    }
                }
                catch (IOException)
                {
                }
            }
        }

        Assert.True(
            firstChance.Count == 0,
            "Unexpected first-chance SQLite exceptions:" + Environment.NewLine + string.Join(Environment.NewLine, firstChance));

        void OnFirstChance(object? sender, System.Runtime.ExceptionServices.FirstChanceExceptionEventArgs e)
        {
            if (e.Exception is Microsoft.Data.Sqlite.SqliteException or DbUpdateException)
            {
                firstChance.Add($"{e.Exception.GetType().Name}: {e.Exception.Message}");
            }
        }
    }

    [Fact]
    public async Task EnsureInitialized_LegacyDb_AddsMissingColumns()
    {
        var path = Path.Combine(Path.GetTempPath(), $"wia-legacy-{Guid.NewGuid():N}.db");
        try
        {
            await using (var conn = new Microsoft.Data.Sqlite.SqliteConnection($"Data Source={path}"))
            {
                await conn.OpenAsync();
                await using var cmd = conn.CreateCommand();
                cmd.CommandText = """
                    CREATE TABLE Events (
                        Id INTEGER PRIMARY KEY AUTOINCREMENT,
                        ComputerName TEXT,
                        LogName TEXT,
                        ProviderName TEXT,
                        EventId INTEGER NOT NULL,
                        TimeCreatedUtc TEXT NOT NULL,
                        Level TEXT,
                        User TEXT,
                        Domain TEXT,
                        ProcessName TEXT,
                        ProcessId INTEGER,
                        ParentProcessName TEXT,
                        ParentProcessId INTEGER,
                        CommandLine TEXT,
                        SourceIpAddress TEXT,
                        DestinationIpAddress TEXT,
                        WorkstationName TEXT,
                        TargetUserName TEXT,
                        TargetDomainName TEXT,
                        RawXml TEXT,
                        PropertiesJson TEXT,
                        ScriptBlock TEXT,
                        ScriptBlockHash TEXT,
                        Hashes TEXT,
                        ProcessGuid TEXT,
                        ParentProcessGuid TEXT,
                        ParentCommandLine TEXT,
                        SourcePort INTEGER,
                        DestinationPort INTEGER,
                        QueryName TEXT,
                        TaskName TEXT,
                        ServiceName TEXT,
                        LogonType INTEGER,
                        ProcessPath TEXT
                    );
                    CREATE TABLE Findings (
                        Id INTEGER PRIMARY KEY AUTOINCREMENT,
                        RuleName TEXT NOT NULL,
                        Title TEXT NOT NULL,
                        Description TEXT,
                        Severity TEXT NOT NULL,
                        TimeUtc TEXT NOT NULL,
                        ComputerName TEXT,
                        User TEXT,
                        SourceIpAddress TEXT,
                        ProcessName TEXT,
                        Details TEXT,
                        RelatedEventRowIds TEXT,
                        CreatedUtc TEXT NOT NULL
                    );
                    CREATE TABLE Iocs (
                        Id INTEGER PRIMARY KEY AUTOINCREMENT,
                        Type TEXT NOT NULL,
                        Value TEXT NOT NULL,
                        Source TEXT,
                        Comment TEXT,
                        ImportedUtc TEXT NOT NULL,
                        UNIQUE(Type, Value)
                    );
                    CREATE TABLE Incidents (
                        Id INTEGER PRIMARY KEY AUTOINCREMENT,
                        Title TEXT NOT NULL,
                        CreatedUtc TEXT NOT NULL,
                        EventsAnalyzed INTEGER NOT NULL,
                        FindingsCritical INTEGER NOT NULL,
                        FindingsHigh INTEGER NOT NULL,
                        FindingsMedium INTEGER NOT NULL,
                        FindingsLow INTEGER NOT NULL,
                        FindingsInfo INTEGER NOT NULL,
                        SummaryJson TEXT
                    );
                    CREATE TABLE Correlations (
                        Id INTEGER PRIMARY KEY AUTOINCREMENT,
                        Scenario TEXT NOT NULL,
                        Title TEXT NOT NULL,
                        Interpretation TEXT,
                        Severity TEXT NOT NULL,
                        TimeUtc TEXT NOT NULL,
                        RelatedEventRowIds TEXT,
                        CreatedUtc TEXT NOT NULL
                    );
                    CREATE TABLE Cves (
                        CveId TEXT NOT NULL PRIMARY KEY,
                        VendorProject TEXT,
                        Product TEXT,
                        VulnerabilityName TEXT,
                        DateAddedUtc TEXT,
                        ShortDescription TEXT,
                        RequiredAction TEXT,
                        DueDateUtc TEXT,
                        KnownRansomwareCampaignUse TEXT,
                        Notes TEXT,
                        Cwes TEXT,
                        Source TEXT NOT NULL,
                        ImportedUtc TEXT NOT NULL
                    );
                    INSERT INTO Events (ComputerName, LogName, ProviderName, EventId, TimeCreatedUtc, User)
                    VALUES ('pc', 'Security', 'Microsoft-Windows-Security-Auditing', 4625, '2026-01-01T00:00:00.0000000Z', 'user1');
                    """;
                await cmd.ExecuteNonQueryAsync();
            }

            Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();

            await using var harness = CreateHarness(path);
            await harness.Database.EnsureInitializedAsync();

            await using var db = await harness.Factory.CreateDbContextAsync();
            var evt = Assert.Single(await db.Events.ToListAsync());
            Assert.False(string.IsNullOrWhiteSpace(evt.EventKey));
            Assert.True(evt.CompletenessScore > 0);
        }
        finally
        {
            Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
            foreach (var leftover in new[] { path, path + "-wal", path + "-shm" })
            {
                try
                {
                    if (File.Exists(leftover))
                    {
                        File.Delete(leftover);
                    }
                }
                catch (IOException)
                {
                }
            }
        }
    }

    private static TestHarness CreateHarness(string path)
    {
        var options = Options.Create(new AnalyzerOptions
        {
            Database = new DatabaseOptions { Path = path }
        });

        var services = new ServiceCollection();
        services.AddSingleton(options);
        services.AddSingleton<IOptions<AnalyzerOptions>>(options);
        services.AddSingleton<InvestigationDatabase>(sp =>
            new InvestigationDatabase(options, NullLogger<InvestigationDatabase>.Instance, sp));
        services.AddDbContextFactory<InvestigationDbContext>((sp, dbOptions) =>
        {
            var database = sp.GetRequiredService<InvestigationDatabase>();
            dbOptions.UseSqlite(database.ConnectionString);
        });

        return new TestHarness(services.BuildServiceProvider());
    }

    private sealed class TestHarness(ServiceProvider provider) : IAsyncDisposable
    {
        public InvestigationDatabase Database { get; } = provider.GetRequiredService<InvestigationDatabase>();

        public IDbContextFactory<InvestigationDbContext> Factory { get; } =
            provider.GetRequiredService<IDbContextFactory<InvestigationDbContext>>();

        public async ValueTask DisposeAsync()
        {
            await Database.DisposeAsync();
            await provider.DisposeAsync();
        }
    }
}
