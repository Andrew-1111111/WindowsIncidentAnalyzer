using WindowsIncidentAnalyzer.Models;

namespace WindowsIncidentAnalyzer.Repositories;

public interface IIncidentRepository
{
    Task<long> InsertAsync(Incident incident, CancellationToken cancellationToken);

    Task<Incident?> GetLatestAsync(CancellationToken cancellationToken);
}
