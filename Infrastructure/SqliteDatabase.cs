using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using WindowsIncidentAnalyzer.Configuration;

namespace WindowsIncidentAnalyzer.Infrastructure;

public sealed class SqliteDatabase : IAsyncDisposable
{
    private readonly ILogger<SqliteDatabase> _logger;
    private readonly string _connectionString;
    private readonly SemaphoreSlim _initLock = new(1, 1);
    private readonly SqliteConnection? _keepAlive;
    private bool _initialized;

    public SqliteDatabase(IOptions<AnalyzerOptions> options, ILogger<SqliteDatabase> logger)
    {
        _logger = logger;
        var path = ConfigurationLoader.ResolveDatabasePath(options.Value);
        var directory = Path.GetDirectoryName(path);
        if (!string.IsNullOrWhiteSpace(directory))
        {
            Directory.CreateDirectory(directory);
        }

        DatabasePath = path;
        _connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = path,
            Mode = SqliteOpenMode.ReadWriteCreate,
            Cache = SqliteCacheMode.Shared
        }.ToString();

        if (string.Equals(path, ":memory:", StringComparison.OrdinalIgnoreCase))
        {
            _keepAlive = new SqliteConnection(_connectionString);
            _keepAlive.Open();
        }
    }

    public string DatabasePath { get; }

    public async Task<SqliteConnection> OpenConnectionAsync(CancellationToken cancellationToken = default)
    {
        await EnsureInitializedAsync(cancellationToken);
        var connection = new SqliteConnection(_connectionString);
        await connection.OpenAsync(cancellationToken);
        await using var pragma = connection.CreateCommand();
        pragma.CommandText = """
            PRAGMA journal_mode=WAL;
            PRAGMA synchronous=NORMAL;
            PRAGMA busy_timeout=5000;
            PRAGMA foreign_keys=ON;
            """;
        await pragma.ExecuteNonQueryAsync(cancellationToken);
        return connection;
    }

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

            await using var connection = new SqliteConnection(_connectionString);
            await connection.OpenAsync(cancellationToken);
            await using var cmd = connection.CreateCommand();
            cmd.CommandText = SchemaSql;
            await cmd.ExecuteNonQueryAsync(cancellationToken);
            await EnsureEventDeduplicationSchemaAsync(connection, cancellationToken);
            await EnsureFindingContextSchemaAsync(connection, cancellationToken);
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

    private static async Task EnsureEventDeduplicationSchemaAsync(
        SqliteConnection connection,
        CancellationToken cancellationToken)
    {
        var columns = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        await using (var info = connection.CreateCommand())
        {
            info.CommandText = "PRAGMA table_info(Events);";
            await using var reader = await info.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                columns.Add(reader.GetString(1));
            }
        }

        foreach (var (name, definition) in new[]
                 {
                     ("EventRecordId", "INTEGER"),
                     ("EventKey", "TEXT"),
                     ("CompletenessScore", "INTEGER NOT NULL DEFAULT 0")
                 })
        {
            if (columns.Contains(name))
            {
                continue;
            }

            await using var alter = connection.CreateCommand();
            alter.CommandText = $"ALTER TABLE Events ADD COLUMN {name} {definition};";
            await alter.ExecuteNonQueryAsync(cancellationToken);
        }

        await BackfillEventKeysAsync(connection, cancellationToken);

        await using var migration = connection.CreateCommand();
        migration.CommandText = """
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

            CREATE UNIQUE INDEX IF NOT EXISTS UX_Events_EventKey ON Events(EventKey);
            """;
        await migration.ExecuteNonQueryAsync(cancellationToken);
    }

    private static async Task EnsureFindingContextSchemaAsync(
        SqliteConnection connection,
        CancellationToken cancellationToken)
    {
        var columns = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        await using (var info = connection.CreateCommand())
        {
            info.CommandText = "PRAGMA table_info(Findings);";
            await using var reader = await info.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                columns.Add(reader.GetString(1));
            }
        }

        if (!columns.Contains("ContextJson"))
        {
            await using var alter = connection.CreateCommand();
            alter.CommandText = "ALTER TABLE Findings ADD COLUMN ContextJson TEXT;";
            await alter.ExecuteNonQueryAsync(cancellationToken);
        }
    }

    private static async Task BackfillEventKeysAsync(
        SqliteConnection connection,
        CancellationToken cancellationToken)
    {
        var rows = new List<(long Id, string? Computer, string? Log, string? Provider, int EventId, string Time, long? RecordId, string? Xml)>();
        await using (var select = connection.CreateCommand())
        {
            select.CommandText = """
                SELECT Id, ComputerName, LogName, ProviderName, EventId, TimeCreatedUtc, EventRecordId, RawXml
                FROM Events
                WHERE EventKey IS NULL OR EventKey = '';
                """;
            await using var reader = await select.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                rows.Add((
                    reader.GetInt64(0),
                    reader.IsDBNull(1) ? null : reader.GetString(1),
                    reader.IsDBNull(2) ? null : reader.GetString(2),
                    reader.IsDBNull(3) ? null : reader.GetString(3),
                    reader.GetInt32(4),
                    reader.GetString(5),
                    reader.IsDBNull(6) ? null : reader.GetInt64(6),
                    reader.IsDBNull(7) ? null : reader.GetString(7)));
            }
        }

        await using var update = connection.CreateCommand();
        update.CommandText = "UPDATE Events SET EventRecordId = $recordId, EventKey = $key WHERE Id = $id;";
        var idParameter = update.Parameters.Add("$id", SqliteType.Integer);
        var recordParameter = update.Parameters.Add("$recordId", SqliteType.Integer);
        var keyParameter = update.Parameters.Add("$key", SqliteType.Text);
        foreach (var row in rows)
        {
            var recordId = row.RecordId ?? EventIdentity.ExtractRecordId(row.Xml);
            var time = DateTimeParser.Parse(row.Time) ?? DateTime.SpecifyKind(DateTime.MinValue, DateTimeKind.Utc);
            idParameter.Value = row.Id;
            recordParameter.Value = (object?)recordId ?? DBNull.Value;
            keyParameter.Value = EventIdentity.BuildKey(
                row.Computer,
                row.Log,
                row.Provider,
                row.EventId,
                time,
                recordId);
            await update.ExecuteNonQueryAsync(cancellationToken);
        }
    }

    private const string SchemaSql = """
        CREATE TABLE IF NOT EXISTS Events (
            Id INTEGER PRIMARY KEY AUTOINCREMENT,
            ComputerName TEXT,
            LogName TEXT,
            ProviderName TEXT,
            EventId INTEGER NOT NULL,
            EventRecordId INTEGER,
            EventKey TEXT,
            CompletenessScore INTEGER NOT NULL DEFAULT 0,
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

        CREATE INDEX IF NOT EXISTS IX_Events_TimeCreatedUtc ON Events(TimeCreatedUtc);
        CREATE INDEX IF NOT EXISTS IX_Events_EventId ON Events(EventId);
        CREATE INDEX IF NOT EXISTS IX_Events_User ON Events(User);
        CREATE INDEX IF NOT EXISTS IX_Events_SourceIp ON Events(SourceIpAddress);
        CREATE INDEX IF NOT EXISTS IX_Events_ProcessName ON Events(ProcessName);
        CREATE INDEX IF NOT EXISTS IX_Events_Host ON Events(ComputerName);
        CREATE INDEX IF NOT EXISTS IX_Events_TargetUser ON Events(TargetUserName);
        CREATE INDEX IF NOT EXISTS IX_Events_ProcessGuid ON Events(ProcessGuid);
        CREATE INDEX IF NOT EXISTS IX_Events_ScriptBlockHash ON Events(ScriptBlockHash);

        CREATE TABLE IF NOT EXISTS Findings (
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

        CREATE INDEX IF NOT EXISTS IX_Findings_Severity ON Findings(Severity);
        CREATE INDEX IF NOT EXISTS IX_Findings_TimeUtc ON Findings(TimeUtc);

        CREATE TABLE IF NOT EXISTS Iocs (
            Id INTEGER PRIMARY KEY AUTOINCREMENT,
            Type TEXT NOT NULL,
            Value TEXT NOT NULL,
            Source TEXT,
            Comment TEXT,
            ImportedUtc TEXT NOT NULL,
            UNIQUE(Type, Value)
        );

        CREATE INDEX IF NOT EXISTS IX_Iocs_Type ON Iocs(Type);

        CREATE TABLE IF NOT EXISTS Incidents (
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

        CREATE TABLE IF NOT EXISTS Correlations (
            Id INTEGER PRIMARY KEY AUTOINCREMENT,
            Scenario TEXT NOT NULL,
            Title TEXT NOT NULL,
            Interpretation TEXT,
            Severity TEXT NOT NULL,
            TimeUtc TEXT NOT NULL,
            User TEXT,
            ComputerName TEXT,
            SourceIpAddress TEXT,
            Details TEXT,
            RelatedEventRowIds TEXT,
            CreatedUtc TEXT NOT NULL
        );
        """;
}
