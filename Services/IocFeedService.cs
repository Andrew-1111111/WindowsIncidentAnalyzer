using System.Collections.Concurrent;
using System.Net;
using System.Net.Http;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using WindowsIncidentAnalyzer.Configuration;
using WindowsIncidentAnalyzer.Infrastructure;
using WindowsIncidentAnalyzer.Models;

namespace WindowsIncidentAnalyzer.Services;

public sealed class IocFeedService(
    IOptions<AnalyzerOptions> options,
    IWebDownloadService webDownload,
    ILogger<IocFeedService> logger) : IIocFeedService
{

    public async Task<IReadOnlyList<Ioc>> DownloadAsync(
        CancellationToken cancellationToken,
        IProgress<string>? progress = null)
    {
        var collected = new ConcurrentBag<Ioc>();
        foreach (var item in BuiltInDefensiveIndicators())
        {
            collected.Add(item);
        }

        var total = Feeds.Length;
        var parallelism = ParallelAnalysis.ResolveIocFeedParallelism(options.Value, total);
        var completed = 0;
        using var gate = parallelism < total ? new SemaphoreSlim(parallelism, parallelism) : null;

        async Task DownloadOneAsync(Feed feed)
        {
            if (gate != null)
            {
                await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
            }

            try
            {
                progress?.Report($"> {feed.Name}");
                using var feedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                feedCts.CancelAfter(ResolveFeedTimeout());

                try
                {
                    await DownloadFeedAsync(feed, collected, feedCts.Token).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
                {
                    logger.LogWarning("Feed {Name} exceeded download timeout", feed.Name);
                }
                catch (Exception ex)
                {
                    logger.LogWarning(ex, "Feed {Name} failed", feed.Name);
                }
            }
            finally
            {
                gate?.Release();
                var done = Interlocked.Increment(ref completed);
                progress?.Report($"[{done}/{total}] {feed.Name}");
            }
        }

        await Task.WhenAll(Feeds.Select(DownloadOneAsync)).ConfigureAwait(false);

        progress?.Report("Deduplicating IOCs...");
        return Deduplicate(collected);
    }

    private async Task DownloadFeedAsync(
        Feed feed,
        ConcurrentBag<Ioc> collected,
        CancellationToken cancellationToken)
    {
        logger.LogInformation("Downloading IOC feed {Name} via {Client}", feed.Name, WebDownloadClients.IocFeeds);

        var urls = feed.AllUrls;
        for (var attempt = 0; attempt < urls.Count; attempt++)
        {
            var url = urls[attempt];
            try
            {
                using var request = new HttpRequestMessage(feed.Method, url);
                if (feed.JsonBody != null)
                {
                    request.Content = new StringContent(feed.JsonBody, System.Text.Encoding.UTF8, "application/json");
                }

                // ResponseContentRead keeps the full body download inside Polly attempt/total timeouts.
                using var response = await webDownload.SendAsync(
                    request,
                    cancellationToken,
                    WebDownloadClients.IocFeeds).ConfigureAwait(false);

                if (!response.IsSuccessStatusCode)
                {
                    logger.LogWarning(
                        "Feed {Name} returned {Status} from {Url}",
                        feed.Name,
                        (int)response.StatusCode,
                        url);
                    continue;
                }

                var body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
                try
                {
                    foreach (var ioc in feed.Parser(body, feed.Name))
                    {
                        collected.Add(ioc);
                    }
                }
                catch (JsonException ex)
                {
                    logger.LogWarning(ex, "Feed {Name} returned invalid JSON from {Url}", feed.Name, url);
                }

                return;
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (OperationCanceledException ex) when (attempt < urls.Count - 1)
            {
                logger.LogDebug(ex, "Feed {Name} timed out from {Url}; trying fallback", feed.Name, url);
            }
            catch (Exception ex) when (attempt < urls.Count - 1)
            {
                logger.LogDebug(ex, "Feed {Name} failed from {Url}; trying fallback", feed.Name, url);
            }
            catch (OperationCanceledException ex)
            {
                logger.LogWarning(ex, "Feed {Name} timed out", feed.Name);
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex, "Feed {Name} could not be downloaded", feed.Name);
            }
        }
    }

    private TimeSpan ResolveFeedTimeout()
    {
        var feedOptions = options.Value.IocFeed;
        if (feedOptions.FeedDownloadTimeoutSeconds > 0)
        {
            return TimeSpan.FromSeconds(feedOptions.FeedDownloadTimeoutSeconds);
        }

        var resilience = options.Value.HttpResilience;
        resilience.Clients.TryGetValue(WebDownloadClients.IocFeeds, out var clientOverride);
        var totalSeconds = clientOverride?.TotalRequestTimeoutSeconds ?? resilience.TotalRequestTimeoutSeconds;
        return TimeSpan.FromSeconds(Math.Max(1, totalSeconds));
    }

    private static List<Ioc> Deduplicate(IEnumerable<Ioc> items)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var result = new List<Ioc>();
        foreach (var ioc in items)
        {
            var value = NormalizeValue(ioc.Type, ioc.Value);
            if (string.IsNullOrWhiteSpace(value) || !IsPlausible(ioc.Type, value))
            {
                continue;
            }

            var key = $"{NormalizeType(ioc.Type)}|{value}";
            if (!seen.Add(key))
            {
                continue;
            }

            result.Add(new Ioc
            {
                Type = NormalizeType(ioc.Type),
                Value = value,
                Source = ioc.Source,
                Comment = ioc.Comment,
                ImportedUtc = DateTime.UtcNow
            });
        }

        return result;
    }

    private static string NormalizeType(string type) => type.Trim().ToLowerInvariant() switch
    {
        "ipv4" or "ipv6" or "ipaddress" => "ip",
        "sha256" or "sha1" or "md5" => "hash",
        "file" or "name" => "filename",
        "host" or "fqdn" or "hostname" => "domain",
        var t => t
    };

    private static string NormalizeValue(string type, string value)
    {
        value = value.Trim().Trim(',', ';', '"', '\'');
        if (value.StartsWith('[') && value.Contains(']'))
        {
            value = value.Replace("[.]", ".").Replace("[://]", "://");
        }

        value = value.Replace("hxxp://", "http://", StringComparison.OrdinalIgnoreCase)
            .Replace("hxxps://", "https://", StringComparison.OrdinalIgnoreCase);

        var kind = NormalizeType(type);
        if (kind == "url")
        {
            if (Uri.TryCreate(value, UriKind.Absolute, out var uri) &&
                (uri.Scheme == Uri.UriSchemeHttp || uri.Scheme == Uri.UriSchemeHttps))
            {
                return uri.ToString();
            }
        }

        if (kind == "domain")
        {
            value = value.Trim('.');
            if (Uri.TryCreate(value, UriKind.Absolute, out var uri))
            {
                return uri.Host;
            }
        }

        if (kind == "ip" && value.Contains('/'))
        {
            value = value.Split('/')[0];
        }

        return value;
    }

    private static bool IsPlausible(string type, string value)
    {
        var kind = NormalizeType(type);
        return kind switch
        {
            "ip" => IPAddress.TryParse(value, out var ip) && !IPAddress.IsLoopback(ip) && !ip.Equals(IPAddress.Any),
            "domain" => value.Contains('.') && !value.Contains(' ') && value.Length is >= 4 and <= 253 &&
                        !value.EndsWith(".localhost", StringComparison.OrdinalIgnoreCase),
            "hash" => Regex.IsMatch(value, "^[A-Fa-f0-9]{32}$|^[A-Fa-f0-9]{40}$|^[A-Fa-f0-9]{64}$"),
            "filename" => value.Length is >= 3 and <= 128 && !value.Contains('\\') && !value.Contains('/'),
            "url" => Uri.TryCreate(value, UriKind.Absolute, out var uri) &&
                     (uri.Scheme == Uri.UriSchemeHttp || uri.Scheme == Uri.UriSchemeHttps),
            _ => false
        };
    }

    private static IEnumerable<Ioc> ParseTextLines(string body, string source, string type, Func<string, string?>? map = null)
    {
        using var reader = new StringReader(body);
        while (reader.ReadLine() is { } line)
        {
            line = line.Trim();
            if (line.Length == 0 || line[0] is '#' or ';' or '/')
            {
                continue;
            }

            if (line.StartsWith("127.0.0.1") || line.StartsWith("0.0.0.0"))
            {
                var parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
                if (parts.Length >= 2)
                {
                    line = parts[1];
                    type = type == "ip" ? "domain" : type;
                }
            }

            var value = map?.Invoke(line) ?? line.Split(' ', '\t', ',', ';')[0];
            if (string.IsNullOrWhiteSpace(value))
            {
                continue;
            }

            yield return new Ioc { Type = type, Value = value, Source = source, Comment = source };
        }
    }

    private static IEnumerable<Ioc> ParseUrlhausCsv(string body, string source)
    {
        using var reader = new StringReader(body);
        while (reader.ReadLine() is { } line)
        {
            if (line.StartsWith('#') || line.Length < 8)
            {
                continue;
            }

            var match = Regex.Match(line, "https?://[^,\"]+", RegexOptions.IgnoreCase);
            if (!match.Success)
            {
                continue;
            }

            var url = match.Value.Trim('"');
            yield return new Ioc { Type = "url", Value = url, Source = source, Comment = source };
            if (Uri.TryCreate(url, UriKind.Absolute, out var uri) && !string.IsNullOrEmpty(uri.Host) && uri.Host.Contains('.'))
            {
                yield return new Ioc { Type = "domain", Value = uri.Host, Source = source, Comment = source };
            }
        }
    }

    private static IEnumerable<Ioc> BuiltInDefensiveIndicators()
    {
        var names = new (string File, string Comment)[]
        {
            ("mimikatz.exe", "Credential dumping tool name"),
            ("procdump.exe", "Sysinternals dump utility often abused post-compromise"),
            ("psexec.exe", "Remote execution utility frequently used for lateral movement"),
            ("psexesvc.exe", "PsExec service binary"),
            ("lazagne.exe", "Credential recovery tool"),
            ("rubeus.exe", "Kerberos attack toolkit name"),
            ("sharphound.exe", "AD collection utility"),
            ("bloodhound.exe", "AD graphing utility"),
            ("seatbelt.exe", "Host recon utility"),
            ("safetykatz.exe", "Credential dumping variant name"),
            ("nanodump.exe", "LSASS dump utility name"),
            ("cobain.exe", "Known infostealer name"),
            ("beacon.exe", "Generic C2 beacon filename (high FP — corroborate)"),
            ("kportscan.exe", "Port scanner"),
            ("nbtscan.exe", "Network scanner"),
            ("adfind.exe", "AD enumeration utility"),
            ("wce.exe", "Windows Credential Editor"),
            ("pwdump.exe", "Password hash dump utility"),
            ("fgdump.exe", "Password hash dump utility"),
            ("gsecdump.exe", "Security dump utility"),
            ("cain.exe", "Cain & Abel"),
            ("anything.exe", "Placeholder ignored"),
        };

        foreach (var (file, comment) in names.Where(n => n.File != "anything.exe"))
        {
            yield return new Ioc { Type = "filename", Value = file, Source = "built-in", Comment = comment };
        }
    }

    private static readonly Feed[] Feeds =
    [
        new("abuse.ch URLhaus recent URLs", "https://urlhaus.abuse.ch/downloads/text_recent/", HttpMethod.Get, null, (body, src) => ParseTextLines(body, src, "url")),
        new("abuse.ch URLhaus online URLs", "https://urlhaus.abuse.ch/downloads/text_online/", HttpMethod.Get, null, (body, src) => ParseTextLines(body, src, "url")),
        new("abuse.ch URLhaus CSV recent", "https://urlhaus.abuse.ch/downloads/csv_recent/", HttpMethod.Get, null, ParseUrlhausCsv),
        new("URLhaus domain filter", "https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-domains.txt", HttpMethod.Get, null, (body, src) => ParseTextLines(body, src, "domain")),
        new("URLhaus hosts filter", "https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-hosts.txt", HttpMethod.Get, null, (body, src) => ParseTextLines(body, src, "domain")),
        new("Emerging Threats compromised IPs", "https://rules.emergingthreats.net/blockrules/compromised-ips.txt", HttpMethod.Get, null, (body, src) => ParseTextLines(body, src, "ip")),
        new("IPsum level 3", "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt", HttpMethod.Get, null, (body, src) => ParseTextLines(body, src, "ip")),
        new("GreenSnow blacklist", "https://blocklist.greensnow.co/greensnow.txt", HttpMethod.Get, null, (body, src) => ParseTextLines(body, src, "ip")),
        new("blocklist.de all", "https://lists.blocklist.de/lists/all.txt", HttpMethod.Get, null, (body, src) => ParseTextLines(body, src, "ip")),
        new("CINS Army bad IPs", "https://cinsscore.com/list/ci-badguys.txt", HttpMethod.Get, null, (body, src) => ParseTextLines(body, src, "ip")),
        new("Spamhaus DROP v4", "https://www.spamhaus.org/drop/drop_v4.json", HttpMethod.Get, null, IocFeedParsers.ParseSpamhausDrop),
        new(
            "Phishing URL blocklist",
            "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt",
            HttpMethod.Get,
            null,
            (body, src) => ParseTextLines(body, src, "url"),
            FallbackUrls: ["https://openphish.com/feed.txt"]),
        new("FireHOL cybercrime IPs", "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/cybercrime.ipset", HttpMethod.Get, null, (body, src) => ParseTextLines(body, src, "ip")),
        new("Public malware SHA-256 list", "https://raw.githubusercontent.com/romainmarcoux/malicious-hash/main/full-hash-sha256-aa.txt", HttpMethod.Get, null, (body, src) => ParseTextLines(body, src, "hash")),
        new("Neo23x0 signature-base C2 IOCs", "https://raw.githubusercontent.com/Neo23x0/signature-base/master/iocs/c2-iocs.txt", HttpMethod.Get, null, ParseMixedIocs)
    ];

    private static IEnumerable<Ioc> ParseMixedIocs(string body, string source)
    {
        using var reader = new StringReader(body);
        while (reader.ReadLine() is { } line)
        {
            line = line.Trim();
            if (line.Length == 0 || line[0] is '#' or ';')
            {
                continue;
            }

            if (Regex.IsMatch(line, @"^(\d{1,3}\.){3}\d{1,3}$"))
            {
                yield return new Ioc { Type = "ip", Value = line, Source = source, Comment = source };
            }
            else if (Regex.IsMatch(line, "^[A-Fa-f0-9]{32}$|^[A-Fa-f0-9]{40}$|^[A-Fa-f0-9]{64}$"))
            {
                yield return new Ioc { Type = "hash", Value = line, Source = source, Comment = source };
            }
            else if (line.StartsWith("http://", StringComparison.OrdinalIgnoreCase) ||
                     line.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
            {
                yield return new Ioc { Type = "url", Value = line, Source = source, Comment = source };
            }
            else
            {
                yield return new Ioc { Type = "domain", Value = line, Source = source, Comment = source };
            }
        }
    }

    private sealed record Feed(
        string Name,
        string Url,
        HttpMethod Method,
        string? JsonBody,
        Func<string, string, IEnumerable<Ioc>> Parser,
        string[]? FallbackUrls = null)
    {
        public IReadOnlyList<string> AllUrls =>
            FallbackUrls is { Length: > 0 }
                ? [Url, ..FallbackUrls]
                : [Url];
    }
}
