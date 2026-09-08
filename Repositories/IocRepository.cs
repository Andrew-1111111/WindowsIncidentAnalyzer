using Microsoft.EntityFrameworkCore;
using WindowsIncidentAnalyzer.Persistence;
using WindowsIncidentAnalyzer.Infrastructure;
using WindowsIncidentAnalyzer.Models;

namespace WindowsIncidentAnalyzer.Repositories;

public sealed class IocRepository(
    IDbContextFactory<InvestigationDbContext> dbFactory,
    InvestigationDatabase database) : IIocRepository
{
    private const int BatchSize = 250;

    public async Task ImportAsync(IReadOnlyList<Ioc> iocs, CancellationToken cancellationToken)
    {
        if (iocs.Count == 0)
        {
            return;
        }

        await database.EnsureInitializedAsync(cancellationToken);
        await using var db = await dbFactory.CreateDbContextAsync(cancellationToken);

        var types = iocs.Select(i => i.Type.Trim().ToLowerInvariant()).Distinct().ToList();
        var values = iocs.Select(i => i.Value.Trim()).Distinct().ToList();

        var existing = await db.Iocs
            .Where(i => types.Contains(i.Type) && values.Contains(i.Value))
            .ToListAsync(cancellationToken);

        var existingMap = existing.ToDictionary(i => (i.Type, i.Value));

        foreach (var ioc in iocs)
        {
            var type = ioc.Type.Trim().ToLowerInvariant();
            var value = ioc.Value.Trim();
            var key = (type, value);
            if (existingMap.TryGetValue(key, out var row))
            {
                row.Source = ioc.Source;
                row.Comment = ioc.Comment;
                row.ImportedUtc = ioc.ImportedUtc;
            }
            else
            {
                var entity = EntityMappers.ToEntity(ioc);
                db.Iocs.Add(entity);
                existingMap[key] = entity;
            }
        }

        await db.SaveChangesAsync(cancellationToken);
    }

    public async Task ReplaceAllAsync(IReadOnlyList<Ioc> iocs, CancellationToken cancellationToken)
    {
        await database.EnsureInitializedAsync(cancellationToken);
        await using var db = await dbFactory.CreateDbContextAsync(cancellationToken);
        await using var tx = await db.Database.BeginTransactionAsync(cancellationToken);

        await db.Iocs.ExecuteDeleteAsync(cancellationToken);

        for (var offset = 0; offset < iocs.Count; offset += BatchSize)
        {
            var batch = iocs.Skip(offset).Take(BatchSize).Select(EntityMappers.ToEntity).ToList();
            db.Iocs.AddRange(batch);
            await db.SaveChangesAsync(cancellationToken);
            db.ChangeTracker.Clear();
        }

        await tx.CommitAsync(cancellationToken);
    }

    public async Task<IReadOnlyList<Ioc>> GetAllAsync(CancellationToken cancellationToken)
    {
        await database.EnsureInitializedAsync(cancellationToken);
        await using var db = await dbFactory.CreateDbContextAsync(cancellationToken);
        var rows = await db.Iocs.AsNoTracking()
            .OrderBy(i => i.Type)
            .ThenBy(i => i.Value)
            .ToListAsync(cancellationToken);
        return rows.ConvertAll(EntityMappers.ToDomain);
    }
}
