using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using WindowsIncidentAnalyzer.Configuration;
using WindowsIncidentAnalyzer.Data;
using WindowsIncidentAnalyzer.Infrastructure;
using WindowsIncidentAnalyzer.Repositories;
using Xunit;

namespace WindowsIncidentAnalyzer.Tests.IntegrationTests;

public sealed class SqliteRepositoryTests
{
    [Fact]
    public async Task EventRepository_RoundTripsNormalizedEvent()
    {
        var path = Path.Combine(Path.GetTempPath(), $"wia-test-{Guid.NewGuid():N}.db");
        try
        {
            await using var harness = CreateHarness(path);
            var repo = new EventRepository(harness.Factory, harness.Database);
            var parser = new WindowsIncidentAnalyzer.Services.EventXmlParser();
            var evt = parser.Parse(WindowsIncidentAnalyzer.Tests.Fixtures.EventXmlFixtures.FailedLogon(
                "2026-08-01T12:00:00.0000000Z", "labuser", "10.0.0.50"));

            var incomplete = new Models.WindowsEvent
            {
                ComputerName = evt.ComputerName,
                LogName = evt.LogName,
                ProviderName = evt.ProviderName,
                EventId = evt.EventId,
                TimeCreatedUtc = evt.TimeCreatedUtc,
                User = "incomplete"
            };

            Assert.Equal(1, await repo.InsertBatchAsync([incomplete], CancellationToken.None));
            Assert.Equal(1, await repo.InsertBatchAsync([evt, evt], CancellationToken.None));
            Assert.Equal(0, await repo.InsertBatchAsync([incomplete], CancellationToken.None));
            var rows = await repo.QueryAsync(new Models.EventQueryFilter
            {
                EventIds = [4625],
                User = "labuser",
                Limit = 10
            }, CancellationToken.None);

            Assert.Single(rows);
            Assert.Equal("10.0.0.50", rows[0].SourceIpAddress);
            Assert.Equal("labuser", rows[0].TargetUserName);
            Assert.NotEqual("incomplete", rows[0].User);
        }
        finally
        {
            CleanupDb(path);
        }
    }

    [Fact]
    public async Task FindingRepository_RoundTripsStructuredContext()
    {
        var path = Path.Combine(Path.GetTempPath(), $"wia-test-{Guid.NewGuid():N}.db");
        try
        {
            await using var harness = CreateHarness(path);
            var repo = new FindingRepository(harness.Factory, harness.Database);
            var finding = new Models.SecurityFinding
            {
                RuleName = "SigmaRules",
                Title = "[Sigma] Test",
                Description = "desc",
                Severity = Models.DetectionSeverity.High,
                TimeUtc = new DateTime(2026, 8, 1, 12, 0, 0, DateTimeKind.Utc),
                Context = new Models.FindingContext
                {
                    RuleId = "111",
                    EventId = 4688,
                    CommandLine = "whoami /all",
                    MatchedFields = ["Image"],
                    MatchedValues = [@"C:\Windows\System32\whoami.exe"],
                    Reason = "Image endswith whoami.exe"
                }
            };

            await repo.InsertManyAsync([finding], CancellationToken.None);
            var rows = await repo.GetAllAsync(10, CancellationToken.None);

            Assert.Single(rows);
            Assert.Equal(4688, rows[0].Context.EventId);
            Assert.Equal("whoami /all", rows[0].Context.CommandLine);
            Assert.Equal(["Image"], rows[0].Context.MatchedFields);
            Assert.Contains("Image endswith", rows[0].Context.Reason);
        }
        finally
        {
            CleanupDb(path);
        }
    }

    [Fact]
    public async Task IocRepository_ReplaceAllAsync_ImportsLargeBatchQuickly()
    {
        var path = Path.Combine(Path.GetTempPath(), $"wia-ioc-{Guid.NewGuid():N}.db");
        try
        {
            await using var harness = CreateHarness(path);
            var repo = new IocRepository(harness.Factory, harness.Database);
            var iocs = Enumerable.Range(0, 5000)
                .Select(i => new Models.Ioc
                {
                    Type = "ip",
                    Value = $"10.0.{i / 256}.{i % 256}",
                    Source = "test",
                    ImportedUtc = DateTime.UtcNow
                })
                .ToList();

            var sw = System.Diagnostics.Stopwatch.StartNew();
            await repo.ReplaceAllAsync(iocs, CancellationToken.None);
            sw.Stop();

            var loaded = await repo.GetAllAsync(CancellationToken.None);
            Assert.Equal(5000, loaded.Count);
            Assert.True(sw.Elapsed < TimeSpan.FromSeconds(10), $"ReplaceAllAsync took {sw.Elapsed.TotalSeconds:F1}s");
        }
        finally
        {
            CleanupDb(path);
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

        var provider = services.BuildServiceProvider();
        return new TestHarness(provider);
    }

    private static void CleanupDb(string path)
    {
        SqliteConnection.ClearAllPools();
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
