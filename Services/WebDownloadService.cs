using WindowsIncidentAnalyzer.Infrastructure;

namespace WindowsIncidentAnalyzer.Services;

public sealed class WebDownloadService(IHttpClientFactory httpClientFactory) : IWebDownloadService
{
    public Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken,
        string clientName = WebDownloadClients.Default) =>
        SendAsync(request, HttpCompletionOption.ResponseContentRead, cancellationToken, clientName);

    public Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        HttpCompletionOption completionOption,
        CancellationToken cancellationToken,
        string clientName = WebDownloadClients.Default)
    {
        var client = httpClientFactory.CreateClient(clientName);
        return client.SendAsync(request, completionOption, cancellationToken);
    }

    public Task<string> GetStringAsync(
        string url,
        CancellationToken cancellationToken,
        string clientName = WebDownloadClients.Default)
    {
        var client = httpClientFactory.CreateClient(clientName);
        return client.GetStringAsync(url, cancellationToken);
    }
}
