using WindowsIncidentAnalyzer.Infrastructure;

namespace WindowsIncidentAnalyzer.Services;

public interface IWebDownloadService
{
    Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken,
        string clientName = WebDownloadClients.Default);

    Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        HttpCompletionOption completionOption,
        CancellationToken cancellationToken,
        string clientName = WebDownloadClients.Default);

    Task<string> GetStringAsync(
        string url,
        CancellationToken cancellationToken,
        string clientName = WebDownloadClients.Default);
}
