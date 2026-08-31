using Microsoft.Data.Sqlite;
using WindowsIncidentAnalyzer.Infrastructure;
using WindowsIncidentAnalyzer.Models;
using WindowsIncidentAnalyzer.Repositories;

namespace WindowsIncidentAnalyzer.Services;

public sealed class StatisticsService(
    SqliteDatabase database,
    IFindingRepository findings) : IStatisticsService
{
    public async Task<StatisticsResult> GetAsync(EventQueryFilter? filter, CancellationToken cancellationToken)
    {
        var result = new StatisticsResult();
        await using var connection = await database.OpenConnectionAsync(cancellationToken);

        result.TotalEvents = Convert.ToInt32(await ScalarAsync(connection, "SELECT COUNT(*) FROM Events", cancellationToken));
        result.EventIdCounts = await MapIntAsync(connection, "SELECT EventId, COUNT(*) FROM Events GROUP BY EventId ORDER BY COUNT(*) DESC LIMIT 30", cancellationToken);
        result.UserCounts = await MapStringAsync(connection, "SELECT COALESCE(User, TargetUserName, '(unknown)'), COUNT(*) FROM Events GROUP BY COALESCE(User, TargetUserName) ORDER BY COUNT(*) DESC LIMIT 20", cancellationToken);
        result.ProcessCounts = await MapStringAsync(connection, "SELECT ProcessName, COUNT(*) FROM Events WHERE ProcessName IS NOT NULL AND ProcessName <> '' GROUP BY ProcessName ORDER BY COUNT(*) DESC LIMIT 20", cancellationToken);
        result.SourceIpCounts = await MapStringAsync(connection, "SELECT SourceIpAddress, COUNT(*) FROM Events WHERE SourceIpAddress IS NOT NULL AND SourceIpAddress <> '' GROUP BY SourceIpAddress ORDER BY COUNT(*) DESC LIMIT 20", cancellationToken);
        result.EventsByHour = await MapIntAsync(connection, "SELECT CAST(strftime('%H', TimeCreatedUtc) AS INTEGER), COUNT(*) FROM Events GROUP BY strftime('%H', TimeCreatedUtc) ORDER BY 1", cancellationToken);

        var findingList = await findings.GetAllAsync(100_000, cancellationToken);
        result.TotalFindings = findingList.Count;
        result.FindingsBySeverity = findingList
            .GroupBy(f => f.Severity)
            .ToDictionary(g => g.Key, g => g.Count());

        return result;
    }

    private static async Task<object?> ScalarAsync(SqliteConnection connection, string sql, CancellationToken ct)
    {
        await using var cmd = connection.CreateCommand();
        cmd.CommandText = sql;
        return await cmd.ExecuteScalarAsync(ct);
    }

    private static async Task<Dictionary<int, int>> MapIntAsync(SqliteConnection connection, string sql, CancellationToken ct)
    {
        var map = new Dictionary<int, int>();
        await using var cmd = connection.CreateCommand();
        cmd.CommandText = sql;
        await using var reader = await cmd.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
        {
            if (reader.IsDBNull(0))
            {
                continue;
            }

            map[Convert.ToInt32(reader.GetValue(0))] = Convert.ToInt32(reader.GetValue(1));
        }

        return map;
    }

    private static async Task<Dictionary<string, int>> MapStringAsync(SqliteConnection connection, string sql, CancellationToken ct)
    {
        var map = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        await using var cmd = connection.CreateCommand();
        cmd.CommandText = sql;
        await using var reader = await cmd.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
        {
            var key = reader.IsDBNull(0) ? "(unknown)" : reader.GetString(0);
            map[key] = Convert.ToInt32(reader.GetValue(1));
        }

        return map;
    }
}
