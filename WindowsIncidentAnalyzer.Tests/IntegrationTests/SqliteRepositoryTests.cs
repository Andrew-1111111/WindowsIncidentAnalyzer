using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Options;
using WindowsIncidentAnalyzer.Configuration;
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
            var options = Options.Create(new AnalyzerOptions
            {
                Database = new DatabaseOptions { Path = path }
            });
            await using (var db = new SqliteDatabase(options, new Microsoft.Extensions.Logging.Abstractions.NullLogger<SqliteDatabase>()))
            {
                var repo = new EventRepository(db);
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
        }
        finally
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
    }

    [Fact]
    public async Task FindingRepository_RoundTripsStructuredContext()
    {
        var path = Path.Combine(Path.GetTempPath(), $"wia-test-{Guid.NewGuid():N}.db");
        try
        {
            var options = Options.Create(new AnalyzerOptions
            {
                Database = new DatabaseOptions { Path = path }
            });
            await using (var db = new SqliteDatabase(options, new Microsoft.Extensions.Logging.Abstractions.NullLogger<SqliteDatabase>()))
            {
                var repo = new FindingRepository(db);
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
        }
        finally
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
    }

    [Fact]
    public async Task IocRepository_ReplaceAllAsync_ImportsLargeBatchQuickly()
    {
        var path = Path.Combine(Path.GetTempPath(), $"wia-ioc-{Guid.NewGuid():N}.db");
        try
        {
            var options = Options.Create(new AnalyzerOptions
            {
                Database = new DatabaseOptions { Path = path }
            });
            await using (var db = new SqliteDatabase(options, new Microsoft.Extensions.Logging.Abstractions.NullLogger<SqliteDatabase>()))
            {
                var repo = new IocRepository(db);
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
        }
        finally
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
    }
}
