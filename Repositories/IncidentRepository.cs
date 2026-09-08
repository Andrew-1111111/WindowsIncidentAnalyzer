using Microsoft.EntityFrameworkCore;
using WindowsIncidentAnalyzer.Data;
using WindowsIncidentAnalyzer.Infrastructure;
using WindowsIncidentAnalyzer.Models;

namespace WindowsIncidentAnalyzer.Repositories;

public sealed class IncidentRepository(
    IDbContextFactory<InvestigationDbContext> dbFactory,
    InvestigationDatabase database) : IIncidentRepository
{
    public async Task<long> InsertAsync(Incident incident, CancellationToken cancellationToken)
    {
        await database.EnsureInitializedAsync(cancellationToken);
        await using var db = await dbFactory.CreateDbContextAsync(cancellationToken);
        var entity = EntityMappers.ToEntity(incident);
        db.Incidents.Add(entity);
        await db.SaveChangesAsync(cancellationToken);
        return entity.Id;
    }

    public async Task<Incident?> GetLatestAsync(CancellationToken cancellationToken)
    {
        await database.EnsureInitializedAsync(cancellationToken);
        await using var db = await dbFactory.CreateDbContextAsync(cancellationToken);
        var entity = await db.Incidents.AsNoTracking()
            .OrderByDescending(i => i.Id)
            .FirstOrDefaultAsync(cancellationToken);
        return entity is null ? null : EntityMappers.ToDomain(entity);
    }
}
