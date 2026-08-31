using Microsoft.Data.Sqlite;
using WindowsIncidentAnalyzer.Infrastructure;
using WindowsIncidentAnalyzer.Models;

namespace WindowsIncidentAnalyzer.Repositories;

public sealed class IocRepository(SqliteDatabase database) : IIocRepository
{
    private const int BatchSize = 250;

    public async Task ImportAsync(IReadOnlyList<Ioc> iocs, CancellationToken cancellationToken)
    {
        if (iocs.Count == 0)
        {
            return;
        }

        await using var connection = await database.OpenConnectionAsync(cancellationToken);
        await using var tx = (SqliteTransaction)await connection.BeginTransactionAsync(cancellationToken);
        await using var cmd = connection.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = """
            INSERT INTO Iocs (Type, Value, Source, Comment, ImportedUtc)
            VALUES ($type, $value, $source, $comment, $imported)
            ON CONFLICT(Type, Value) DO UPDATE SET
                Source = excluded.Source,
                Comment = excluded.Comment,
                ImportedUtc = excluded.ImportedUtc;
            """;

        var type = cmd.Parameters.Add("$type", SqliteType.Text);
        var value = cmd.Parameters.Add("$value", SqliteType.Text);
        var source = cmd.Parameters.Add("$source", SqliteType.Text);
        var comment = cmd.Parameters.Add("$comment", SqliteType.Text);
        var imported = cmd.Parameters.Add("$imported", SqliteType.Text);

        foreach (var ioc in iocs)
        {
            type.Value = ioc.Type.Trim().ToLowerInvariant();
            value.Value = ioc.Value.Trim();
            source.Value = (object?)ioc.Source ?? DBNull.Value;
            comment.Value = (object?)ioc.Comment ?? DBNull.Value;
            imported.Value = DateTimeParser.Iso(ioc.ImportedUtc);
            await cmd.ExecuteNonQueryAsync(cancellationToken);
        }

        await tx.CommitAsync(cancellationToken);
    }

    public async Task ReplaceAllAsync(IReadOnlyList<Ioc> iocs, CancellationToken cancellationToken)
    {
        await using var connection = await database.OpenConnectionAsync(cancellationToken);
        await using var tx = (SqliteTransaction)await connection.BeginTransactionAsync(cancellationToken);
        await using (var delete = connection.CreateCommand())
        {
            delete.Transaction = tx;
            delete.CommandText = "DELETE FROM Iocs;";
            await delete.ExecuteNonQueryAsync(cancellationToken);
        }

        await InsertBatchesAsync(connection, tx, iocs, cancellationToken);
        await tx.CommitAsync(cancellationToken);
    }

    private static async Task InsertBatchesAsync(
        SqliteConnection connection,
        SqliteTransaction tx,
        IReadOnlyList<Ioc> iocs,
        CancellationToken cancellationToken)
    {
        for (var offset = 0; offset < iocs.Count; offset += BatchSize)
        {
            var batch = iocs.Skip(offset).Take(BatchSize).ToList();
            await using var cmd = connection.CreateCommand();
            cmd.Transaction = tx;

            var values = new List<string>(batch.Count);
            for (var i = 0; i < batch.Count; i++)
            {
                var ioc = batch[i];
                values.Add($"($t{i}, $v{i}, $s{i}, $c{i}, $iu{i})");
                cmd.Parameters.AddWithValue($"$t{i}", ioc.Type.Trim().ToLowerInvariant());
                cmd.Parameters.AddWithValue($"$v{i}", ioc.Value.Trim());
                cmd.Parameters.AddWithValue($"$s{i}", (object?)ioc.Source ?? DBNull.Value);
                cmd.Parameters.AddWithValue($"$c{i}", (object?)ioc.Comment ?? DBNull.Value);
                cmd.Parameters.AddWithValue($"$iu{i}", DateTimeParser.Iso(ioc.ImportedUtc));
            }

            cmd.CommandText =
                "INSERT INTO Iocs (Type, Value, Source, Comment, ImportedUtc) VALUES " +
                string.Join(", ", values);
            await cmd.ExecuteNonQueryAsync(cancellationToken);
        }
    }

    public async Task<IReadOnlyList<Ioc>> GetAllAsync(CancellationToken cancellationToken)
    {
        await using var connection = await database.OpenConnectionAsync(cancellationToken);
        await using var cmd = connection.CreateCommand();
        cmd.CommandText = "SELECT * FROM Iocs ORDER BY Type, Value";
        var list = new List<Ioc>();
        await using var reader = await cmd.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            list.Add(new Ioc
            {
                Id = reader.GetInt64(reader.GetOrdinal("Id")),
                Type = reader["Type"] as string ?? string.Empty,
                Value = reader["Value"] as string ?? string.Empty,
                Source = reader["Source"] as string,
                Comment = reader["Comment"] as string,
                ImportedUtc = DateTimeParser.Parse(reader["ImportedUtc"] as string) ?? DateTime.UtcNow
            });
        }

        return list;
    }
}
