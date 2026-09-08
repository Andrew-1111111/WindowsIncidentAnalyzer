using Microsoft.EntityFrameworkCore;
using WindowsIncidentAnalyzer.Persistence;
using WindowsIncidentAnalyzer.Infrastructure;
using WindowsIncidentAnalyzer.Models;

namespace WindowsIncidentAnalyzer.Repositories;

public sealed class FindingRepository(
    IDbContextFactory<InvestigationDbContext> dbFactory,
    InvestigationDatabase database) : IFindingRepository
{
    public async Task InsertManyAsync(IReadOnlyList<SecurityFinding> findings, CancellationToken cancellationToken)
    {
        if (findings.Count == 0)
        {
            return;
        }

        await database.EnsureInitializedAsync(cancellationToken);
        await using var db = await dbFactory.CreateDbContextAsync(cancellationToken);
        db.Findings.AddRange(findings.Select(EntityMappers.ToEntity));
        await db.SaveChangesAsync(cancellationToken);
    }

    public async Task<IReadOnlyList<SecurityFinding>> GetAllAsync(int limit, CancellationToken cancellationToken)
    {
        await database.EnsureInitializedAsync(cancellationToken);
        await using var db = await dbFactory.CreateDbContextAsync(cancellationToken);
        var take = limit <= 0 ? 10000 : limit;

        var rows = await db.Findings.AsNoTracking()
            .OrderBy(f => f.Severity == "Critical" ? 0
                : f.Severity == "High" ? 1
                : f.Severity == "Medium" ? 2
                : f.Severity == "Low" ? 3
                : 4)
            .ThenBy(f => f.TimeUtc)
            .Take(take)
            .ToListAsync(cancellationToken);

        return rows.ConvertAll(EntityMappers.ToDomain);
    }

    public async Task ClearAsync(CancellationToken cancellationToken)
    {
        await database.EnsureInitializedAsync(cancellationToken);
        await using var db = await dbFactory.CreateDbContextAsync(cancellationToken);
        await db.Findings.ExecuteDeleteAsync(cancellationToken);
    }
}
