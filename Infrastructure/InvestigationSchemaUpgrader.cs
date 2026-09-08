using Microsoft.EntityFrameworkCore;
using WindowsIncidentAnalyzer.Persistence;

namespace WindowsIncidentAnalyzer.Infrastructure;

/// <summary>
/// Upgrades older on-disk databases that predate EventKey / CompletenessScore / ContextJson.
/// EnsureCreated does not alter existing tables.
/// </summary>
internal static class InvestigationSchemaUpgrader
{
    public static async Task ApplyConnectionPragmasAsync(
        InvestigationDbContext db,
        CancellationToken cancellationToken)
    {
        await db.Database.ExecuteSqlRawAsync("PRAGMA journal_mode=WAL;", cancellationToken);
        await db.Database.ExecuteSqlRawAsync("PRAGMA synchronous=NORMAL;", cancellationToken);
        await db.Database.ExecuteSqlRawAsync("PRAGMA busy_timeout=5000;", cancellationToken);
        await db.Database.ExecuteSqlRawAsync("PRAGMA foreign_keys=ON;", cancellationToken);
    }

    public static async Task EnsureCompatibleSchemaAsync(
        InvestigationDbContext db,
        CancellationToken cancellationToken)
    {
        var eventColumns = await GetColumnNamesAsync(db, "Events", cancellationToken);
        var addedEventColumns = false;

        if (!eventColumns.Contains("EventRecordId"))
        {
            await db.Database.ExecuteSqlRawAsync(
                "ALTER TABLE Events ADD COLUMN EventRecordId INTEGER;",
                cancellationToken);
            addedEventColumns = true;
        }

        if (!eventColumns.Contains("EventKey"))
        {
            await db.Database.ExecuteSqlRawAsync(
                "ALTER TABLE Events ADD COLUMN EventKey TEXT;",
                cancellationToken);
            addedEventColumns = true;
        }

        if (!eventColumns.Contains("CompletenessScore"))
        {
            await db.Database.ExecuteSqlRawAsync(
                "ALTER TABLE Events ADD COLUMN CompletenessScore INTEGER NOT NULL DEFAULT 0;",
                cancellationToken);
            addedEventColumns = true;
        }

        if (addedEventColumns || await db.Events.AnyAsync(e => e.EventKey == null || e.EventKey == "", cancellationToken))
        {
            await BackfillEventKeysAsync(db, cancellationToken);
            await db.Database.ExecuteSqlRawAsync(
                """
                UPDATE Events
                SET CompletenessScore =
                    (ComputerName IS NOT NULL AND ComputerName <> '') +
                    (LogName IS NOT NULL AND LogName <> '') +
                    (ProviderName IS NOT NULL AND ProviderName <> '') +
                    (Level IS NOT NULL AND Level <> '') +
                    (User IS NOT NULL AND User <> '') +
                    (Domain IS NOT NULL AND Domain <> '') +
                    (ProcessName IS NOT NULL AND ProcessName <> '') +
                    (ProcessId IS NOT NULL) +
                    (ParentProcessName IS NOT NULL AND ParentProcessName <> '') +
                    (ParentProcessId IS NOT NULL) +
                    (CommandLine IS NOT NULL AND CommandLine <> '') +
                    (SourceIpAddress IS NOT NULL AND SourceIpAddress <> '') +
                    (DestinationIpAddress IS NOT NULL AND DestinationIpAddress <> '') +
                    (WorkstationName IS NOT NULL AND WorkstationName <> '') +
                    (TargetUserName IS NOT NULL AND TargetUserName <> '') +
                    (TargetDomainName IS NOT NULL AND TargetDomainName <> '') +
                    (ScriptBlock IS NOT NULL AND ScriptBlock <> '') +
                    (Hashes IS NOT NULL AND Hashes <> '') +
                    (ProcessGuid IS NOT NULL AND ProcessGuid <> '') +
                    (ParentProcessGuid IS NOT NULL AND ParentProcessGuid <> '') +
                    (ParentCommandLine IS NOT NULL AND ParentCommandLine <> '') +
                    (SourcePort IS NOT NULL) +
                    (DestinationPort IS NOT NULL) +
                    (QueryName IS NOT NULL AND QueryName <> '') +
                    (TaskName IS NOT NULL AND TaskName <> '') +
                    (ServiceName IS NOT NULL AND ServiceName <> '') +
                    (LogonType IS NOT NULL) +
                    (ProcessPath IS NOT NULL AND ProcessPath <> '') +
                    min(20, length(coalesce(PropertiesJson, '')) / 128) +
                    min(20, length(coalesce(RawXml, '')) / 256);
                """,
                cancellationToken);
            await db.Database.ExecuteSqlRawAsync(
                """
                DELETE FROM Events
                WHERE Id IN (
                    SELECT Id
                    FROM (
                        SELECT Id,
                               row_number() OVER (
                                   PARTITION BY EventKey
                                   ORDER BY CompletenessScore DESC, Id DESC
                               ) AS duplicate_number
                        FROM Events
                    )
                    WHERE duplicate_number > 1
                );
                """,
                cancellationToken);
            await db.Database.ExecuteSqlRawAsync(
                "CREATE UNIQUE INDEX IF NOT EXISTS UX_Events_EventKey ON Events(EventKey);",
                cancellationToken);
        }

        var findingColumns = await GetColumnNamesAsync(db, "Findings", cancellationToken);
        if (!findingColumns.Contains("ContextJson"))
        {
            await db.Database.ExecuteSqlRawAsync(
                "ALTER TABLE Findings ADD COLUMN ContextJson TEXT;",
                cancellationToken);
        }
    }

    private static async Task BackfillEventKeysAsync(
        InvestigationDbContext db,
        CancellationToken cancellationToken)
    {
        var rows = await db.Events
            .AsNoTracking()
            .Where(e => e.EventKey == null || e.EventKey == "")
            .Select(e => new
            {
                e.Id,
                e.ComputerName,
                e.LogName,
                e.ProviderName,
                e.EventId,
                e.TimeCreatedUtc,
                e.EventRecordId,
                e.RawXml
            })
            .ToListAsync(cancellationToken);

        if (rows.Count == 0)
        {
            return;
        }

        foreach (var row in rows)
        {
            var recordId = row.EventRecordId ?? EventIdentity.ExtractRecordId(row.RawXml);
            var key = EventIdentity.BuildKey(
                row.ComputerName,
                row.LogName,
                row.ProviderName,
                row.EventId,
                row.TimeCreatedUtc,
                recordId);

            await db.Events
                .Where(e => e.Id == row.Id)
                .ExecuteUpdateAsync(
                    setters => setters
                        .SetProperty(e => e.EventRecordId, recordId)
                        .SetProperty(e => e.EventKey, key),
                    cancellationToken);
        }
    }

    private static async Task<HashSet<string>> GetColumnNamesAsync(
        InvestigationDbContext db,
        string tableName,
        CancellationToken cancellationToken)
    {
        var sql = tableName switch
        {
            "Events" => "SELECT name AS Name FROM pragma_table_info('Events');",
            "Findings" => "SELECT name AS Name FROM pragma_table_info('Findings');",
            _ => throw new ArgumentOutOfRangeException(nameof(tableName), tableName, "Unsupported table.")
        };

        var names = await db.Database
            .SqlQueryRaw<ColumnNameRow>(sql)
            .ToListAsync(cancellationToken);

        return names
            .Select(n => n.Name)
            .Where(n => !string.IsNullOrWhiteSpace(n))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
    }

    private sealed class ColumnNameRow
    {
        public string Name { get; set; } = string.Empty;
    }
}
