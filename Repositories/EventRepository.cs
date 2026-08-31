using System.Text.Json;
using Microsoft.Data.Sqlite;
using WindowsIncidentAnalyzer.Infrastructure;
using WindowsIncidentAnalyzer.Models;

namespace WindowsIncidentAnalyzer.Repositories;

public sealed class EventRepository(SqliteDatabase database) : IEventRepository
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
    };

    public async Task<int> InsertBatchAsync(IReadOnlyList<WindowsEvent> events, CancellationToken cancellationToken)
    {
        if (events.Count == 0)
        {
            return 0;
        }

        await using var connection = await database.OpenConnectionAsync(cancellationToken);
        await using var transaction = (SqliteTransaction)await connection.BeginTransactionAsync(cancellationToken);
        await using var cmd = connection.CreateCommand();
        cmd.Transaction = transaction;
        cmd.CommandText = """
            INSERT INTO Events (
                ComputerName, LogName, ProviderName, EventId, EventRecordId, EventKey, CompletenessScore,
                TimeCreatedUtc, Level, User, Domain,
                ProcessName, ProcessId, ParentProcessName, ParentProcessId, CommandLine,
                SourceIpAddress, DestinationIpAddress, WorkstationName, TargetUserName, TargetDomainName,
                RawXml, PropertiesJson, ScriptBlock, ScriptBlockHash, Hashes, ProcessGuid, ParentProcessGuid,
                ParentCommandLine, SourcePort, DestinationPort, QueryName, TaskName, ServiceName, LogonType, ProcessPath
            ) VALUES (
                $computer, $log, $provider, $eventId, $recordId, $eventKey, $score,
                $time, $level, $user, $domain,
                $process, $pid, $parent, $ppid, $cmd,
                $sip, $dip, $workstation, $targetUser, $targetDomain,
                $xml, $props, $script, $scriptHash, $hashes, $guid, $pguid,
                $pcmd, $sport, $dport, $query, $task, $service, $logonType, $path
            )
            ON CONFLICT(EventKey) DO UPDATE SET
                ComputerName = coalesce(excluded.ComputerName, Events.ComputerName),
                LogName = coalesce(excluded.LogName, Events.LogName),
                ProviderName = coalesce(excluded.ProviderName, Events.ProviderName),
                EventId = excluded.EventId,
                EventRecordId = coalesce(excluded.EventRecordId, Events.EventRecordId),
                CompletenessScore = excluded.CompletenessScore,
                TimeCreatedUtc = excluded.TimeCreatedUtc,
                Level = coalesce(excluded.Level, Events.Level),
                User = coalesce(excluded.User, Events.User),
                Domain = coalesce(excluded.Domain, Events.Domain),
                ProcessName = coalesce(excluded.ProcessName, Events.ProcessName),
                ProcessId = coalesce(excluded.ProcessId, Events.ProcessId),
                ParentProcessName = coalesce(excluded.ParentProcessName, Events.ParentProcessName),
                ParentProcessId = coalesce(excluded.ParentProcessId, Events.ParentProcessId),
                CommandLine = coalesce(excluded.CommandLine, Events.CommandLine),
                SourceIpAddress = coalesce(excluded.SourceIpAddress, Events.SourceIpAddress),
                DestinationIpAddress = coalesce(excluded.DestinationIpAddress, Events.DestinationIpAddress),
                WorkstationName = coalesce(excluded.WorkstationName, Events.WorkstationName),
                TargetUserName = coalesce(excluded.TargetUserName, Events.TargetUserName),
                TargetDomainName = coalesce(excluded.TargetDomainName, Events.TargetDomainName),
                RawXml = coalesce(excluded.RawXml, Events.RawXml),
                PropertiesJson = coalesce(excluded.PropertiesJson, Events.PropertiesJson),
                ScriptBlock = coalesce(excluded.ScriptBlock, Events.ScriptBlock),
                ScriptBlockHash = coalesce(excluded.ScriptBlockHash, Events.ScriptBlockHash),
                Hashes = coalesce(excluded.Hashes, Events.Hashes),
                ProcessGuid = coalesce(excluded.ProcessGuid, Events.ProcessGuid),
                ParentProcessGuid = coalesce(excluded.ParentProcessGuid, Events.ParentProcessGuid),
                ParentCommandLine = coalesce(excluded.ParentCommandLine, Events.ParentCommandLine),
                SourcePort = coalesce(excluded.SourcePort, Events.SourcePort),
                DestinationPort = coalesce(excluded.DestinationPort, Events.DestinationPort),
                QueryName = coalesce(excluded.QueryName, Events.QueryName),
                TaskName = coalesce(excluded.TaskName, Events.TaskName),
                ServiceName = coalesce(excluded.ServiceName, Events.ServiceName),
                LogonType = coalesce(excluded.LogonType, Events.LogonType),
                ProcessPath = coalesce(excluded.ProcessPath, Events.ProcessPath)
            WHERE excluded.CompletenessScore > Events.CompletenessScore;
            """;

        var computer = cmd.Parameters.Add("$computer", SqliteType.Text);
        var log = cmd.Parameters.Add("$log", SqliteType.Text);
        var provider = cmd.Parameters.Add("$provider", SqliteType.Text);
        var eventId = cmd.Parameters.Add("$eventId", SqliteType.Integer);
        var recordId = cmd.Parameters.Add("$recordId", SqliteType.Integer);
        var eventKey = cmd.Parameters.Add("$eventKey", SqliteType.Text);
        var score = cmd.Parameters.Add("$score", SqliteType.Integer);
        var time = cmd.Parameters.Add("$time", SqliteType.Text);
        var level = cmd.Parameters.Add("$level", SqliteType.Text);
        var user = cmd.Parameters.Add("$user", SqliteType.Text);
        var domain = cmd.Parameters.Add("$domain", SqliteType.Text);
        var process = cmd.Parameters.Add("$process", SqliteType.Text);
        var pid = cmd.Parameters.Add("$pid", SqliteType.Integer);
        var parent = cmd.Parameters.Add("$parent", SqliteType.Text);
        var ppid = cmd.Parameters.Add("$ppid", SqliteType.Integer);
        var cmdline = cmd.Parameters.Add("$cmd", SqliteType.Text);
        var sip = cmd.Parameters.Add("$sip", SqliteType.Text);
        var dip = cmd.Parameters.Add("$dip", SqliteType.Text);
        var workstation = cmd.Parameters.Add("$workstation", SqliteType.Text);
        var targetUser = cmd.Parameters.Add("$targetUser", SqliteType.Text);
        var targetDomain = cmd.Parameters.Add("$targetDomain", SqliteType.Text);
        var xml = cmd.Parameters.Add("$xml", SqliteType.Text);
        var props = cmd.Parameters.Add("$props", SqliteType.Text);
        var script = cmd.Parameters.Add("$script", SqliteType.Text);
        var scriptHash = cmd.Parameters.Add("$scriptHash", SqliteType.Text);
        var hashes = cmd.Parameters.Add("$hashes", SqliteType.Text);
        var guid = cmd.Parameters.Add("$guid", SqliteType.Text);
        var pguid = cmd.Parameters.Add("$pguid", SqliteType.Text);
        var pcmd = cmd.Parameters.Add("$pcmd", SqliteType.Text);
        var sport = cmd.Parameters.Add("$sport", SqliteType.Integer);
        var dport = cmd.Parameters.Add("$dport", SqliteType.Integer);
        var query = cmd.Parameters.Add("$query", SqliteType.Text);
        var task = cmd.Parameters.Add("$task", SqliteType.Text);
        var service = cmd.Parameters.Add("$service", SqliteType.Text);
        var logonType = cmd.Parameters.Add("$logonType", SqliteType.Integer);
        var path = cmd.Parameters.Add("$path", SqliteType.Text);

        var affected = 0;
        foreach (var evt in events)
        {
            cancellationToken.ThrowIfCancellationRequested();
            computer.Value = (object?)evt.ComputerName ?? DBNull.Value;
            log.Value = (object?)evt.LogName ?? DBNull.Value;
            provider.Value = (object?)evt.ProviderName ?? DBNull.Value;
            eventId.Value = evt.EventId;
            recordId.Value = (object?)evt.EventRecordId ?? DBNull.Value;
            eventKey.Value = EventIdentity.BuildKey(evt);
            score.Value = CalculateCompletenessScore(evt);
            time.Value = DateTimeParser.Iso(evt.TimeCreatedUtc);
            level.Value = (object?)evt.Level ?? DBNull.Value;
            user.Value = (object?)evt.User ?? DBNull.Value;
            domain.Value = (object?)evt.Domain ?? DBNull.Value;
            process.Value = (object?)evt.ProcessName ?? DBNull.Value;
            pid.Value = (object?)evt.ProcessId ?? DBNull.Value;
            parent.Value = (object?)evt.ParentProcessName ?? DBNull.Value;
            ppid.Value = (object?)evt.ParentProcessId ?? DBNull.Value;
            cmdline.Value = (object?)evt.CommandLine ?? DBNull.Value;
            sip.Value = (object?)evt.SourceIpAddress ?? DBNull.Value;
            dip.Value = (object?)evt.DestinationIpAddress ?? DBNull.Value;
            workstation.Value = (object?)evt.WorkstationName ?? DBNull.Value;
            targetUser.Value = (object?)evt.TargetUserName ?? DBNull.Value;
            targetDomain.Value = (object?)evt.TargetDomainName ?? DBNull.Value;
            xml.Value = (object?)evt.RawXml ?? DBNull.Value;
            props.Value = JsonSerializer.Serialize(evt.Properties, JsonOptions);
            script.Value = (object?)evt.ScriptBlock ?? DBNull.Value;
            scriptHash.Value = (object?)evt.ScriptBlockHash ?? DBNull.Value;
            hashes.Value = (object?)evt.Hashes ?? DBNull.Value;
            guid.Value = (object?)evt.ProcessGuid ?? DBNull.Value;
            pguid.Value = (object?)evt.ParentProcessGuid ?? DBNull.Value;
            pcmd.Value = (object?)evt.ParentCommandLine ?? DBNull.Value;
            sport.Value = (object?)evt.SourcePort ?? DBNull.Value;
            dport.Value = (object?)evt.DestinationPort ?? DBNull.Value;
            query.Value = (object?)evt.QueryName ?? DBNull.Value;
            task.Value = (object?)evt.TaskName ?? DBNull.Value;
            service.Value = (object?)evt.ServiceName ?? DBNull.Value;
            logonType.Value = (object?)evt.LogonType ?? DBNull.Value;
            path.Value = (object?)evt.ProcessPath ?? DBNull.Value;
            affected += await cmd.ExecuteNonQueryAsync(cancellationToken);
        }

        await transaction.CommitAsync(cancellationToken);
        return affected;
    }

    internal static int CalculateCompletenessScore(WindowsEvent evt)
    {
        var values = new[]
        {
            evt.ComputerName, evt.LogName, evt.ProviderName, evt.Level, evt.User, evt.Domain,
            evt.ProcessName, evt.ParentProcessName, evt.CommandLine, evt.SourceIpAddress,
            evt.DestinationIpAddress, evt.WorkstationName, evt.TargetUserName, evt.TargetDomainName,
            evt.ScriptBlock, evt.ScriptBlockHash, evt.Hashes, evt.ProcessGuid, evt.ParentProcessGuid,
            evt.ParentCommandLine, evt.QueryName, evt.TaskName, evt.ServiceName, evt.ProcessPath
        };
        var score = values.Count(value => !string.IsNullOrWhiteSpace(value));
        score += evt.EventRecordId.HasValue ? 1 : 0;
        score += evt.ProcessId.HasValue ? 1 : 0;
        score += evt.ParentProcessId.HasValue ? 1 : 0;
        score += evt.SourcePort.HasValue ? 1 : 0;
        score += evt.DestinationPort.HasValue ? 1 : 0;
        score += evt.LogonType.HasValue ? 1 : 0;
        score += Math.Min(20, evt.Properties.Count);
        score += Math.Min(20, (evt.RawXml?.Length ?? 0) / 256);
        return score;
    }

    public async Task<IReadOnlyList<WindowsEvent>> QueryAsync(EventQueryFilter filter, CancellationToken cancellationToken)
    {
        await using var connection = await database.OpenConnectionAsync(cancellationToken);
        await using var cmd = connection.CreateCommand();
        cmd.CommandText = "SELECT * FROM Events WHERE 1=1" + AppendFilters(cmd, filter) +
                          " ORDER BY TimeCreatedUtc ASC LIMIT $limit OFFSET $offset";
        cmd.Parameters.AddWithValue("$limit", filter.Limit <= 0 ? 1000 : filter.Limit);
        cmd.Parameters.AddWithValue("$offset", filter.Offset);
        return await ReadEventsAsync(cmd, cancellationToken);
    }

    public async Task<int> CountAsync(EventQueryFilter? filter, CancellationToken cancellationToken)
    {
        await using var connection = await database.OpenConnectionAsync(cancellationToken);
        await using var cmd = connection.CreateCommand();
        cmd.CommandText = "SELECT COUNT(*) FROM Events WHERE 1=1" + AppendFilters(cmd, filter ?? new EventQueryFilter { Limit = int.MaxValue });
        var result = await cmd.ExecuteScalarAsync(cancellationToken);
        return Convert.ToInt32(result);
    }

    public async Task<IReadOnlyList<WindowsEvent>> GetByEventIdsAsync(
        IReadOnlyList<int> eventIds,
        EventQueryFilter? filter,
        CancellationToken cancellationToken)
    {
        var merged = new EventQueryFilter
        {
            EventIds = eventIds,
            User = filter?.User,
            IpAddress = filter?.IpAddress,
            ProcessName = filter?.ProcessName,
            Keyword = filter?.Keyword,
            FromUtc = filter?.FromUtc,
            ToUtc = filter?.ToUtc,
            TimeRanges = filter?.TimeRanges,
            ComputerName = filter?.ComputerName,
            LogName = filter?.LogName,
            Limit = filter?.Limit is > 0 ? filter.Limit : 100000,
            Offset = filter?.Offset ?? 0
        };
        return await QueryAsync(merged, cancellationToken);
    }

    public async Task<IReadOnlyDictionary<long, WindowsEvent>> GetByRowIdsAsync(
        IReadOnlyList<long> rowIds,
        CancellationToken cancellationToken)
    {
        if (rowIds.Count == 0)
        {
            return new Dictionary<long, WindowsEvent>();
        }

        var map = new Dictionary<long, WindowsEvent>();
        const int batchSize = 500;
        await using var connection = await database.OpenConnectionAsync(cancellationToken);

        for (var offset = 0; offset < rowIds.Count; offset += batchSize)
        {
            var batch = rowIds.Skip(offset).Take(batchSize).ToList();
            await using var cmd = connection.CreateCommand();
            var names = new List<string>(batch.Count);
            for (var i = 0; i < batch.Count; i++)
            {
                var name = $"$id{i}";
                names.Add(name);
                cmd.Parameters.AddWithValue(name, batch[i]);
            }

            cmd.CommandText = $"SELECT * FROM Events WHERE Id IN ({string.Join(",", names)})";
            foreach (var evt in await ReadEventsAsync(cmd, cancellationToken))
            {
                map[evt.Id] = evt;
            }
        }

        return map;
    }

    private static string AppendFilters(SqliteCommand cmd, EventQueryFilter filter)
    {
        var sql = string.Empty;
        if (filter.EventIds is { Count: > 0 })
        {
            var names = new List<string>();
            for (var i = 0; i < filter.EventIds.Count; i++)
            {
                var name = $"$eid{i}";
                names.Add(name);
                cmd.Parameters.AddWithValue(name, filter.EventIds[i]);
            }

            sql += $" AND EventId IN ({string.Join(",", names)})";
        }

        if (!string.IsNullOrWhiteSpace(filter.User))
        {
            sql += " AND (User LIKE $user OR TargetUserName LIKE $user OR Domain LIKE $user)";
            cmd.Parameters.AddWithValue("$user", $"%{filter.User}%");
        }

        if (!string.IsNullOrWhiteSpace(filter.IpAddress))
        {
            sql += " AND (SourceIpAddress LIKE $ip OR DestinationIpAddress LIKE $ip OR WorkstationName LIKE $ip)";
            cmd.Parameters.AddWithValue("$ip", $"%{filter.IpAddress}%");
        }

        if (!string.IsNullOrWhiteSpace(filter.ProcessName))
        {
            sql += " AND (ProcessName LIKE $proc OR ParentProcessName LIKE $proc OR ProcessPath LIKE $proc OR CommandLine LIKE $proc)";
            cmd.Parameters.AddWithValue("$proc", $"%{filter.ProcessName}%");
        }

        if (!string.IsNullOrWhiteSpace(filter.Keyword))
        {
            sql += """
                 AND (
                    RawXml LIKE $kw OR PropertiesJson LIKE $kw OR CommandLine LIKE $kw OR ScriptBlock LIKE $kw
                    OR ProcessName LIKE $kw OR User LIKE $kw OR TargetUserName LIKE $kw OR QueryName LIKE $kw
                    OR TaskName LIKE $kw OR ServiceName LIKE $kw OR Hashes LIKE $kw
                 )
                """;
            cmd.Parameters.AddWithValue("$kw", $"%{filter.Keyword}%");
        }

        if (filter.TimeRanges is { Count: > 0 } ranges)
        {
            var parts = new List<string>(ranges.Count);
            for (var i = 0; i < ranges.Count; i++)
            {
                parts.Add($"(TimeCreatedUtc >= $from{i} AND TimeCreatedUtc <= $to{i})");
                cmd.Parameters.AddWithValue($"$from{i}", DateTimeParser.Iso(ranges[i].FromUtc));
                cmd.Parameters.AddWithValue($"$to{i}", DateTimeParser.Iso(ranges[i].ToUtc));
            }

            sql += " AND (" + string.Join(" OR ", parts) + ")";
        }
        else
        {
            if (filter.FromUtc is { } from)
            {
                sql += " AND TimeCreatedUtc >= $from";
                cmd.Parameters.AddWithValue("$from", DateTimeParser.Iso(from));
            }

            if (filter.ToUtc is { } to)
            {
                sql += " AND TimeCreatedUtc <= $to";
                cmd.Parameters.AddWithValue("$to", DateTimeParser.Iso(to));
            }
        }

        if (!string.IsNullOrWhiteSpace(filter.ComputerName))
        {
            sql += " AND ComputerName LIKE $host";
            cmd.Parameters.AddWithValue("$host", $"%{filter.ComputerName}%");
        }

        if (!string.IsNullOrWhiteSpace(filter.LogName))
        {
            sql += " AND LogName LIKE $logName";
            cmd.Parameters.AddWithValue("$logName", $"%{filter.LogName}%");
        }

        return sql;
    }

    internal static async Task<List<WindowsEvent>> ReadEventsAsync(SqliteCommand cmd, CancellationToken cancellationToken)
    {
        var results = new List<WindowsEvent>();
        await using var reader = await cmd.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            results.Add(Map(reader));
        }

        return results;
    }

    private static WindowsEvent Map(SqliteDataReader reader)
    {
        var propsJson = reader["PropertiesJson"] as string;
        Dictionary<string, string> properties;
        try
        {
            properties = string.IsNullOrWhiteSpace(propsJson)
                ? new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                : JsonSerializer.Deserialize<Dictionary<string, string>>(propsJson, JsonOptions)
                  ?? new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        }
        catch (JsonException)
        {
            properties = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        }

        return new WindowsEvent
        {
            Id = reader.GetInt64(reader.GetOrdinal("Id")),
            ComputerName = reader["ComputerName"] as string,
            LogName = reader["LogName"] as string,
            ProviderName = reader["ProviderName"] as string,
            EventId = Convert.ToInt32(reader["EventId"]),
            EventRecordId = reader["EventRecordId"] is DBNull ? null : Convert.ToInt64(reader["EventRecordId"]),
            TimeCreatedUtc = DateTimeParser.Parse(reader["TimeCreatedUtc"] as string) ?? DateTime.MinValue,
            Level = reader["Level"] as string,
            User = reader["User"] as string,
            Domain = reader["Domain"] as string,
            ProcessName = reader["ProcessName"] as string,
            ProcessId = reader["ProcessId"] is DBNull ? null : Convert.ToInt32(reader["ProcessId"]),
            ParentProcessName = reader["ParentProcessName"] as string,
            ParentProcessId = reader["ParentProcessId"] is DBNull ? null : Convert.ToInt32(reader["ParentProcessId"]),
            CommandLine = reader["CommandLine"] as string,
            SourceIpAddress = reader["SourceIpAddress"] as string,
            DestinationIpAddress = reader["DestinationIpAddress"] as string,
            WorkstationName = reader["WorkstationName"] as string,
            TargetUserName = reader["TargetUserName"] as string,
            TargetDomainName = reader["TargetDomainName"] as string,
            RawXml = reader["RawXml"] as string,
            Properties = properties,
            ScriptBlock = reader["ScriptBlock"] as string,
            ScriptBlockHash = reader["ScriptBlockHash"] as string,
            Hashes = reader["Hashes"] as string,
            ProcessGuid = reader["ProcessGuid"] as string,
            ParentProcessGuid = reader["ParentProcessGuid"] as string,
            ParentCommandLine = reader["ParentCommandLine"] as string,
            SourcePort = reader["SourcePort"] is DBNull ? null : Convert.ToInt32(reader["SourcePort"]),
            DestinationPort = reader["DestinationPort"] is DBNull ? null : Convert.ToInt32(reader["DestinationPort"]),
            QueryName = reader["QueryName"] as string,
            TaskName = reader["TaskName"] as string,
            ServiceName = reader["ServiceName"] as string,
            LogonType = reader["LogonType"] is DBNull ? null : Convert.ToInt32(reader["LogonType"]),
            ProcessPath = reader["ProcessPath"] as string
        };
    }
}
