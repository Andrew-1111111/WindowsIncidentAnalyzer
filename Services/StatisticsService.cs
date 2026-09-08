using Microsoft.EntityFrameworkCore;
using WindowsIncidentAnalyzer.Persistence;
using WindowsIncidentAnalyzer.Infrastructure;
using WindowsIncidentAnalyzer.Models;
using WindowsIncidentAnalyzer.Repositories;

namespace WindowsIncidentAnalyzer.Services;

public sealed class StatisticsService(
    IDbContextFactory<InvestigationDbContext> dbFactory,
    InvestigationDatabase database,
    IFindingRepository findings) : IStatisticsService
{
    public async Task<StatisticsResult> GetAsync(EventQueryFilter? filter, CancellationToken cancellationToken)
    {
        await database.EnsureInitializedAsync(cancellationToken);
        await using var db = await dbFactory.CreateDbContextAsync(cancellationToken);

        var result = new StatisticsResult
        {
            TotalEvents = await db.Events.AsNoTracking().CountAsync(cancellationToken)
        };

        result.EventIdCounts = await db.Events.AsNoTracking()
            .GroupBy(e => e.EventId)
            .Select(g => new { Key = g.Key, Count = g.Count() })
            .OrderByDescending(x => x.Count)
            .Take(30)
            .ToDictionaryAsync(x => x.Key, x => x.Count, cancellationToken);

        var userGroups = await db.Events.AsNoTracking()
            .Select(e => e.User ?? e.TargetUserName)
            .GroupBy(u => u)
            .Select(g => new { Key = g.Key, Count = g.Count() })
            .OrderByDescending(x => x.Count)
            .Take(20)
            .ToListAsync(cancellationToken);
        result.UserCounts = userGroups.ToDictionary(
            x => x.Key ?? "(unknown)",
            x => x.Count,
            StringComparer.OrdinalIgnoreCase);

        var processGroups = await db.Events.AsNoTracking()
            .Where(e => e.ProcessName != null && e.ProcessName != "")
            .GroupBy(e => e.ProcessName!)
            .Select(g => new { Key = g.Key, Count = g.Count() })
            .OrderByDescending(x => x.Count)
            .Take(20)
            .ToListAsync(cancellationToken);
        result.ProcessCounts = processGroups.ToDictionary(
            x => x.Key,
            x => x.Count,
            StringComparer.OrdinalIgnoreCase);

        var ipGroups = await db.Events.AsNoTracking()
            .Where(e => e.SourceIpAddress != null && e.SourceIpAddress != "")
            .GroupBy(e => e.SourceIpAddress!)
            .Select(g => new { Key = g.Key, Count = g.Count() })
            .OrderByDescending(x => x.Count)
            .Take(20)
            .ToListAsync(cancellationToken);
        result.SourceIpCounts = ipGroups.ToDictionary(
            x => x.Key,
            x => x.Count,
            StringComparer.OrdinalIgnoreCase);

        var hours = await db.Events.AsNoTracking()
            .Select(e => e.TimeCreatedUtc)
            .ToListAsync(cancellationToken);
        result.EventsByHour = hours
            .GroupBy(t => t.Hour)
            .OrderBy(g => g.Key)
            .ToDictionary(g => g.Key, g => g.Count());

        var findingList = await findings.GetAllAsync(100_000, cancellationToken);
        result.TotalFindings = findingList.Count;
        result.FindingsBySeverity = findingList
            .GroupBy(f => f.Severity)
            .ToDictionary(g => g.Key, g => g.Count());

        return result;
    }
}
