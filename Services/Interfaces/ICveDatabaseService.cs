namespace WindowsIncidentAnalyzer.Services;

public interface ICveDatabaseService
{
    Task EnsureLoadedAsync(CancellationToken cancellationToken);

    Task<int> LoadFromFileAsync(string path, CancellationToken cancellationToken);

    Task<int> UpdateFromCisaKevAsync(CancellationToken cancellationToken);

    int Count { get; }
}
