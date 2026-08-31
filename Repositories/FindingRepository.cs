using System.Text.Json;
using Microsoft.Data.Sqlite;
using WindowsIncidentAnalyzer.Infrastructure;
using WindowsIncidentAnalyzer.Models;

namespace WindowsIncidentAnalyzer.Repositories;

public sealed class FindingRepository(SqliteDatabase database) : IFindingRepository
{
    public async Task InsertManyAsync(IReadOnlyList<SecurityFinding> findings, CancellationToken cancellationToken)
    {
        if (findings.Count == 0)
        {
            return;
        }

        await using var connection = await database.OpenConnectionAsync(cancellationToken);
        await using var tx = (SqliteTransaction)await connection.BeginTransactionAsync(cancellationToken);
        await using var cmd = connection.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = """
            INSERT INTO Findings (
                RuleName, Title, Description, Severity, TimeUtc, ComputerName, User, SourceIpAddress,
                ProcessName, Details, RelatedEventRowIds, ContextJson, CreatedUtc
            ) VALUES (
                $rule, $title, $desc, $sev, $time, $host, $user, $ip, $proc, $details, $related, $context, $created
            );
            """;

        var rule = cmd.Parameters.Add("$rule", SqliteType.Text);
        var title = cmd.Parameters.Add("$title", SqliteType.Text);
        var desc = cmd.Parameters.Add("$desc", SqliteType.Text);
        var sev = cmd.Parameters.Add("$sev", SqliteType.Text);
        var time = cmd.Parameters.Add("$time", SqliteType.Text);
        var host = cmd.Parameters.Add("$host", SqliteType.Text);
        var user = cmd.Parameters.Add("$user", SqliteType.Text);
        var ip = cmd.Parameters.Add("$ip", SqliteType.Text);
        var proc = cmd.Parameters.Add("$proc", SqliteType.Text);
        var details = cmd.Parameters.Add("$details", SqliteType.Text);
        var related = cmd.Parameters.Add("$related", SqliteType.Text);
        var context = cmd.Parameters.Add("$context", SqliteType.Text);
        var created = cmd.Parameters.Add("$created", SqliteType.Text);

        foreach (var finding in findings)
        {
            rule.Value = finding.RuleName;
            title.Value = finding.Title;
            desc.Value = (object?)finding.Description ?? DBNull.Value;
            sev.Value = finding.Severity.ToString();
            time.Value = DateTimeParser.Iso(finding.TimeUtc);
            host.Value = (object?)finding.ComputerName ?? DBNull.Value;
            user.Value = (object?)finding.User ?? DBNull.Value;
            ip.Value = (object?)finding.SourceIpAddress ?? DBNull.Value;
            proc.Value = (object?)finding.ProcessName ?? DBNull.Value;
            details.Value = (object?)finding.Details ?? DBNull.Value;
            related.Value = JsonSerializer.Serialize(finding.RelatedEventRowIds);
            context.Value = (object?)FindingContextSerializer.Serialize(finding.Context) ?? DBNull.Value;
            created.Value = DateTimeParser.Iso(finding.CreatedUtc);
            await cmd.ExecuteNonQueryAsync(cancellationToken);
        }

        await tx.CommitAsync(cancellationToken);
    }

    public async Task<IReadOnlyList<SecurityFinding>> GetAllAsync(int limit, CancellationToken cancellationToken)
    {
        await using var connection = await database.OpenConnectionAsync(cancellationToken);
        await using var cmd = connection.CreateCommand();
        cmd.CommandText = """
            SELECT * FROM Findings
            ORDER BY CASE Severity
                WHEN 'Critical' THEN 0 WHEN 'High' THEN 1 WHEN 'Medium' THEN 2 WHEN 'Low' THEN 3 ELSE 4 END,
                TimeUtc ASC
            LIMIT $limit
            """;
        cmd.Parameters.AddWithValue("$limit", limit <= 0 ? 10000 : limit);

        var list = new List<SecurityFinding>();
        await using var reader = await cmd.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            var findingContext = HasColumn(reader, "ContextJson")
                ? FindingContextSerializer.Deserialize(reader["ContextJson"] as string)
                : new FindingContext();

            var finding = new SecurityFinding
            {
                Id = reader.GetInt64(reader.GetOrdinal("Id")),
                RuleName = reader["RuleName"] as string ?? string.Empty,
                Title = reader["Title"] as string ?? string.Empty,
                Description = reader["Description"] as string ?? string.Empty,
                Severity = Enum.TryParse<DetectionSeverity>(reader["Severity"] as string, out var sev) ? sev : DetectionSeverity.Info,
                TimeUtc = DateTimeParser.Parse(reader["TimeUtc"] as string) ?? DateTime.MinValue,
                ComputerName = reader["ComputerName"] as string,
                User = reader["User"] as string,
                SourceIpAddress = reader["SourceIpAddress"] as string,
                ProcessName = reader["ProcessName"] as string,
                Details = reader["Details"] as string,
                RelatedEventRowIds = DeserializeIds(reader["RelatedEventRowIds"] as string),
                CreatedUtc = DateTimeParser.Parse(reader["CreatedUtc"] as string) ?? DateTime.UtcNow
            };

            FindingContextMapper.SyncLegacyFields(finding, findingContext);
            list.Add(finding);
        }

        return list;
    }

    public async Task ClearAsync(CancellationToken cancellationToken)
    {
        await using var connection = await database.OpenConnectionAsync(cancellationToken);
        await using var cmd = connection.CreateCommand();
        cmd.CommandText = "DELETE FROM Findings;";
        await cmd.ExecuteNonQueryAsync(cancellationToken);
    }

    internal static List<long> DeserializeIds(string? json)
    {
        if (string.IsNullOrWhiteSpace(json))
        {
            return [];
        }

        try
        {
            return JsonSerializer.Deserialize<List<long>>(json) ?? [];
        }
        catch (JsonException)
        {
            return [];
        }
    }

    private static bool HasColumn(SqliteDataReader reader, string columnName)
    {
        for (var i = 0; i < reader.FieldCount; i++)
        {
            if (reader.GetName(i).Equals(columnName, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }
}
