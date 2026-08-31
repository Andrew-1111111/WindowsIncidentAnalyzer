using Microsoft.Data.Sqlite;
using WindowsIncidentAnalyzer.Infrastructure;
using WindowsIncidentAnalyzer.Models;

namespace WindowsIncidentAnalyzer.Repositories;

public sealed class IncidentRepository(SqliteDatabase database) : IIncidentRepository
{
    public async Task<long> InsertAsync(Incident incident, CancellationToken cancellationToken)
    {
        await using var connection = await database.OpenConnectionAsync(cancellationToken);
        await using var cmd = connection.CreateCommand();
        cmd.CommandText = """
            INSERT INTO Incidents (
                Title, CreatedUtc, EventsAnalyzed, FindingsCritical, FindingsHigh, FindingsMedium, FindingsLow, FindingsInfo, SummaryJson
            ) VALUES ($title, $created, $events, $c, $h, $m, $l, $i, $summary);
            SELECT last_insert_rowid();
            """;
        cmd.Parameters.AddWithValue("$title", incident.Title);
        cmd.Parameters.AddWithValue("$created", DateTimeParser.Iso(incident.CreatedUtc));
        cmd.Parameters.AddWithValue("$events", incident.EventsAnalyzed);
        cmd.Parameters.AddWithValue("$c", incident.FindingsCritical);
        cmd.Parameters.AddWithValue("$h", incident.FindingsHigh);
        cmd.Parameters.AddWithValue("$m", incident.FindingsMedium);
        cmd.Parameters.AddWithValue("$l", incident.FindingsLow);
        cmd.Parameters.AddWithValue("$i", incident.FindingsInfo);
        cmd.Parameters.AddWithValue("$summary", (object?)incident.SummaryJson ?? DBNull.Value);
        var id = await cmd.ExecuteScalarAsync(cancellationToken);
        return Convert.ToInt64(id);
    }

    public async Task<Incident?> GetLatestAsync(CancellationToken cancellationToken)
    {
        await using var connection = await database.OpenConnectionAsync(cancellationToken);
        await using var cmd = connection.CreateCommand();
        cmd.CommandText = "SELECT * FROM Incidents ORDER BY Id DESC LIMIT 1";
        await using var reader = await cmd.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken))
        {
            return null;
        }

        return new Incident
        {
            Id = reader.GetInt64(reader.GetOrdinal("Id")),
            Title = reader["Title"] as string ?? string.Empty,
            CreatedUtc = DateTimeParser.Parse(reader["CreatedUtc"] as string) ?? DateTime.UtcNow,
            EventsAnalyzed = Convert.ToInt32(reader["EventsAnalyzed"]),
            FindingsCritical = Convert.ToInt32(reader["FindingsCritical"]),
            FindingsHigh = Convert.ToInt32(reader["FindingsHigh"]),
            FindingsMedium = Convert.ToInt32(reader["FindingsMedium"]),
            FindingsLow = Convert.ToInt32(reader["FindingsLow"]),
            FindingsInfo = Convert.ToInt32(reader["FindingsInfo"]),
            SummaryJson = reader["SummaryJson"] as string
        };
    }
}

public sealed class CorrelationRepository(SqliteDatabase database) : ICorrelationRepository
{
    public async Task InsertManyAsync(IReadOnlyList<EventCorrelation> correlations, CancellationToken cancellationToken)
    {
        if (correlations.Count == 0)
        {
            return;
        }

        await using var connection = await database.OpenConnectionAsync(cancellationToken);
        await using var tx = (SqliteTransaction)await connection.BeginTransactionAsync(cancellationToken);
        await using var cmd = connection.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = """
            INSERT INTO Correlations (
                Scenario, Title, Interpretation, Severity, TimeUtc, User, ComputerName, SourceIpAddress, Details, RelatedEventRowIds, CreatedUtc
            ) VALUES (
                $scenario, $title, $interp, $sev, $time, $user, $host, $ip, $details, $related, $created
            );
            """;

        foreach (var item in correlations)
        {
            cmd.Parameters.Clear();
            cmd.Parameters.AddWithValue("$scenario", item.Scenario);
            cmd.Parameters.AddWithValue("$title", item.Title);
            cmd.Parameters.AddWithValue("$interp", item.Interpretation);
            cmd.Parameters.AddWithValue("$sev", item.Severity.ToString());
            cmd.Parameters.AddWithValue("$time", DateTimeParser.Iso(item.TimeUtc));
            cmd.Parameters.AddWithValue("$user", (object?)item.User ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$host", (object?)item.ComputerName ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$ip", (object?)item.SourceIpAddress ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$details", item.Details);
            cmd.Parameters.AddWithValue("$related", System.Text.Json.JsonSerializer.Serialize(item.RelatedEventRowIds));
            cmd.Parameters.AddWithValue("$created", DateTimeParser.Iso(item.CreatedUtc));
            await cmd.ExecuteNonQueryAsync(cancellationToken);
        }

        await tx.CommitAsync(cancellationToken);
    }

    public async Task<IReadOnlyList<EventCorrelation>> GetAllAsync(int limit, CancellationToken cancellationToken)
    {
        await using var connection = await database.OpenConnectionAsync(cancellationToken);
        await using var cmd = connection.CreateCommand();
        cmd.CommandText = "SELECT * FROM Correlations ORDER BY TimeUtc ASC LIMIT $limit";
        cmd.Parameters.AddWithValue("$limit", limit <= 0 ? 10000 : limit);
        var list = new List<EventCorrelation>();
        await using var reader = await cmd.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            list.Add(new EventCorrelation
            {
                Id = reader.GetInt64(reader.GetOrdinal("Id")),
                Scenario = reader["Scenario"] as string ?? string.Empty,
                Title = reader["Title"] as string ?? string.Empty,
                Interpretation = reader["Interpretation"] as string ?? string.Empty,
                Severity = Enum.TryParse<DetectionSeverity>(reader["Severity"] as string, out var sev) ? sev : DetectionSeverity.Medium,
                TimeUtc = DateTimeParser.Parse(reader["TimeUtc"] as string) ?? DateTime.MinValue,
                User = reader["User"] as string,
                ComputerName = reader["ComputerName"] as string,
                SourceIpAddress = reader["SourceIpAddress"] as string,
                Details = reader["Details"] as string ?? string.Empty,
                RelatedEventRowIds = FindingRepository.DeserializeIds(reader["RelatedEventRowIds"] as string),
                CreatedUtc = DateTimeParser.Parse(reader["CreatedUtc"] as string) ?? DateTime.UtcNow
            });
        }

        return list;
    }

    public async Task ClearAsync(CancellationToken cancellationToken)
    {
        await using var connection = await database.OpenConnectionAsync(cancellationToken);
        await using var cmd = connection.CreateCommand();
        cmd.CommandText = "DELETE FROM Correlations;";
        await cmd.ExecuteNonQueryAsync(cancellationToken);
    }
}
