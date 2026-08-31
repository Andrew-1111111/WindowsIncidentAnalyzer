using WindowsIncidentAnalyzer.Models;

namespace WindowsIncidentAnalyzer.Repositories;

public interface IIocRepository
{
    Task ImportAsync(IReadOnlyList<Ioc> iocs, CancellationToken cancellationToken);

    Task ReplaceAllAsync(IReadOnlyList<Ioc> iocs, CancellationToken cancellationToken);

    Task<IReadOnlyList<Ioc>> GetAllAsync(CancellationToken cancellationToken);
}
