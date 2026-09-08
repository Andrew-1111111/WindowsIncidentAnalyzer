using Microsoft.EntityFrameworkCore;
using WindowsIncidentAnalyzer.Persistence;
using WindowsIncidentAnalyzer.Persistence.Entities;
using WindowsIncidentAnalyzer.Infrastructure;
using WindowsIncidentAnalyzer.Models;

namespace WindowsIncidentAnalyzer.Repositories;

public sealed class EventRepository(
    IDbContextFactory<InvestigationDbContext> dbFactory,
    InvestigationDatabase database) : IEventRepository
{
    public async Task<int> InsertBatchAsync(IReadOnlyList<WindowsEvent> events, CancellationToken cancellationToken)
    {
        if (events.Count == 0)
        {
            return 0;
        }

        await database.EnsureInitializedAsync(cancellationToken);
        await using var db = await dbFactory.CreateDbContextAsync(cancellationToken);

        var prepared = new List<(WindowsEvent Event, string Key, int Score)>(events.Count);
        foreach (var evt in events)
        {
            prepared.Add((evt, EventIdentity.BuildKey(evt), CalculateCompletenessScore(evt)));
        }

        var keys = prepared.Select(p => p.Key).Distinct().ToList();
        var existing = await db.Events
            .Where(e => e.EventKey != null && keys.Contains(e.EventKey))
            .ToDictionaryAsync(e => e.EventKey!, cancellationToken);

        var affected = 0;
        foreach (var (evt, key, score) in prepared)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!existing.TryGetValue(key, out var row))
            {
                var entity = EntityMappers.ToEntity(evt, key, score);
                db.Events.Add(entity);
                existing[key] = entity;
                affected++;
            }
            else if (score > row.CompletenessScore)
            {
                EntityMappers.MergeRicher(row, evt, score);
                affected++;
            }
        }

        if (affected > 0)
        {
            await db.SaveChangesAsync(cancellationToken);
        }

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
        await database.EnsureInitializedAsync(cancellationToken);
        await using var db = await dbFactory.CreateDbContextAsync(cancellationToken);

        var limit = filter.Limit <= 0 ? 1000 : filter.Limit;
        var query = ApplyFilters(db.Events.AsNoTracking(), filter)
            .OrderBy(e => e.TimeCreatedUtc)
            .Skip(filter.Offset)
            .Take(limit);

        var rows = await query.ToListAsync(cancellationToken);
        return rows.ConvertAll(EntityMappers.ToDomain);
    }

    public async Task<int> CountAsync(EventQueryFilter? filter, CancellationToken cancellationToken)
    {
        await database.EnsureInitializedAsync(cancellationToken);
        await using var db = await dbFactory.CreateDbContextAsync(cancellationToken);
        var effective = filter ?? new EventQueryFilter { Limit = int.MaxValue };
        return await ApplyFilters(db.Events.AsNoTracking(), effective).CountAsync(cancellationToken);
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

        await database.EnsureInitializedAsync(cancellationToken);
        await using var db = await dbFactory.CreateDbContextAsync(cancellationToken);

        var map = new Dictionary<long, WindowsEvent>();
        const int batchSize = 500;
        for (var offset = 0; offset < rowIds.Count; offset += batchSize)
        {
            var batch = rowIds.Skip(offset).Take(batchSize).ToList();
            var rows = await db.Events.AsNoTracking()
                .Where(e => batch.Contains(e.Id))
                .ToListAsync(cancellationToken);
            foreach (var row in rows)
            {
                map[row.Id] = EntityMappers.ToDomain(row);
            }
        }

        return map;
    }

    internal static IQueryable<EventEntity> ApplyFilters(IQueryable<EventEntity> query, EventQueryFilter filter)
    {
        if (filter.EventIds is { Count: > 0 } eventIds)
        {
            query = query.Where(e => eventIds.Contains(e.EventId));
        }

        if (!string.IsNullOrWhiteSpace(filter.User))
        {
            var pattern = $"%{filter.User}%";
            query = query.Where(e =>
                (e.User != null && EF.Functions.Like(e.User, pattern)) ||
                (e.TargetUserName != null && EF.Functions.Like(e.TargetUserName, pattern)) ||
                (e.Domain != null && EF.Functions.Like(e.Domain, pattern)));
        }

        if (!string.IsNullOrWhiteSpace(filter.IpAddress))
        {
            var pattern = $"%{filter.IpAddress}%";
            query = query.Where(e =>
                (e.SourceIpAddress != null && EF.Functions.Like(e.SourceIpAddress, pattern)) ||
                (e.DestinationIpAddress != null && EF.Functions.Like(e.DestinationIpAddress, pattern)) ||
                (e.WorkstationName != null && EF.Functions.Like(e.WorkstationName, pattern)));
        }

        if (!string.IsNullOrWhiteSpace(filter.ProcessName))
        {
            var pattern = $"%{filter.ProcessName}%";
            query = query.Where(e =>
                (e.ProcessName != null && EF.Functions.Like(e.ProcessName, pattern)) ||
                (e.ParentProcessName != null && EF.Functions.Like(e.ParentProcessName, pattern)) ||
                (e.ProcessPath != null && EF.Functions.Like(e.ProcessPath, pattern)) ||
                (e.CommandLine != null && EF.Functions.Like(e.CommandLine, pattern)));
        }

        if (!string.IsNullOrWhiteSpace(filter.Keyword))
        {
            var pattern = $"%{filter.Keyword}%";
            query = query.Where(e =>
                (e.RawXml != null && EF.Functions.Like(e.RawXml, pattern)) ||
                (e.PropertiesJson != null && EF.Functions.Like(e.PropertiesJson, pattern)) ||
                (e.CommandLine != null && EF.Functions.Like(e.CommandLine, pattern)) ||
                (e.ScriptBlock != null && EF.Functions.Like(e.ScriptBlock, pattern)) ||
                (e.ProcessName != null && EF.Functions.Like(e.ProcessName, pattern)) ||
                (e.User != null && EF.Functions.Like(e.User, pattern)) ||
                (e.TargetUserName != null && EF.Functions.Like(e.TargetUserName, pattern)) ||
                (e.QueryName != null && EF.Functions.Like(e.QueryName, pattern)) ||
                (e.TaskName != null && EF.Functions.Like(e.TaskName, pattern)) ||
                (e.ServiceName != null && EF.Functions.Like(e.ServiceName, pattern)) ||
                (e.Hashes != null && EF.Functions.Like(e.Hashes, pattern)));
        }

        if (filter.TimeRanges is { Count: > 0 } ranges)
        {
            IQueryable<EventEntity>? matched = null;
            foreach (var range in ranges)
            {
                var from = range.FromUtc;
                var to = range.ToUtc;
                var part = query.Where(e => e.TimeCreatedUtc >= from && e.TimeCreatedUtc <= to);
                matched = matched is null ? part : matched.Union(part);
            }

            query = matched!;
        }
        else
        {
            if (filter.FromUtc is { } from)
            {
                query = query.Where(e => e.TimeCreatedUtc >= from);
            }

            if (filter.ToUtc is { } to)
            {
                query = query.Where(e => e.TimeCreatedUtc <= to);
            }
        }

        if (!string.IsNullOrWhiteSpace(filter.ComputerName))
        {
            var pattern = $"%{filter.ComputerName}%";
            query = query.Where(e => e.ComputerName != null && EF.Functions.Like(e.ComputerName, pattern));
        }

        if (!string.IsNullOrWhiteSpace(filter.LogName))
        {
            var pattern = $"%{filter.LogName}%";
            query = query.Where(e => e.LogName != null && EF.Functions.Like(e.LogName, pattern));
        }

        return query;
    }
}
