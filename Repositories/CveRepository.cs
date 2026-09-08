using Microsoft.EntityFrameworkCore;
using WindowsIncidentAnalyzer.Data;
using WindowsIncidentAnalyzer.Infrastructure;
using WindowsIncidentAnalyzer.Models;

namespace WindowsIncidentAnalyzer.Repositories;

public sealed class CveRepository(
    IDbContextFactory<InvestigationDbContext> dbFactory,
    InvestigationDatabase database) : ICveRepository
{
    private const int BatchSize = 250;

    public int Count { get; private set; }

    public async Task ReplaceAllAsync(IReadOnlyList<CveRecord> records, CancellationToken cancellationToken)
    {
        await database.EnsureInitializedAsync(cancellationToken);
        await using var db = await dbFactory.CreateDbContextAsync(cancellationToken);
        await using var tx = await db.Database.BeginTransactionAsync(cancellationToken);

        await db.Cves.ExecuteDeleteAsync(cancellationToken);

        for (var offset = 0; offset < records.Count; offset += BatchSize)
        {
            var batch = records.Skip(offset).Take(BatchSize).Select(EntityMappers.ToEntity).ToList();
            db.Cves.AddRange(batch);
            await db.SaveChangesAsync(cancellationToken);
            db.ChangeTracker.Clear();
        }

        await tx.CommitAsync(cancellationToken);
        Count = records.Count;
    }

    public async Task<IReadOnlyList<CveRecord>> GetAllAsync(CancellationToken cancellationToken)
    {
        await database.EnsureInitializedAsync(cancellationToken);
        await using var db = await dbFactory.CreateDbContextAsync(cancellationToken);
        var rows = await db.Cves.AsNoTracking()
            .OrderBy(c => c.CveId)
            .ToListAsync(cancellationToken);
        Count = rows.Count;
        return rows.ConvertAll(EntityMappers.ToDomain);
    }
}
