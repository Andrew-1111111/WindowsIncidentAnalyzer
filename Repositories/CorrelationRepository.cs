using Microsoft.EntityFrameworkCore;
using WindowsIncidentAnalyzer.Persistence;
using WindowsIncidentAnalyzer.Infrastructure;
using WindowsIncidentAnalyzer.Models;

namespace WindowsIncidentAnalyzer.Repositories;

public sealed class CorrelationRepository(
    IDbContextFactory<InvestigationDbContext> dbFactory,
    InvestigationDatabase database) : ICorrelationRepository
{
    public async Task InsertManyAsync(IReadOnlyList<EventCorrelation> correlations, CancellationToken cancellationToken)
    {
        if (correlations.Count == 0)
        {
            return;
        }

        await database.EnsureInitializedAsync(cancellationToken);
        await using var db = await dbFactory.CreateDbContextAsync(cancellationToken);
        db.Correlations.AddRange(correlations.Select(EntityMappers.ToEntity));
        await db.SaveChangesAsync(cancellationToken);
    }

    public async Task<IReadOnlyList<EventCorrelation>> GetAllAsync(int limit, CancellationToken cancellationToken)
    {
        await database.EnsureInitializedAsync(cancellationToken);
        await using var db = await dbFactory.CreateDbContextAsync(cancellationToken);
        var take = limit <= 0 ? 10000 : limit;
        var rows = await db.Correlations.AsNoTracking()
            .OrderBy(c => c.TimeUtc)
            .Take(take)
            .ToListAsync(cancellationToken);
        return rows.ConvertAll(EntityMappers.ToDomain);
    }

    public async Task ClearAsync(CancellationToken cancellationToken)
    {
        await database.EnsureInitializedAsync(cancellationToken);
        await using var db = await dbFactory.CreateDbContextAsync(cancellationToken);
        await db.Correlations.ExecuteDeleteAsync(cancellationToken);
    }
}
