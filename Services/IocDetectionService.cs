using System.Collections.Concurrent;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using WindowsIncidentAnalyzer.Configuration;
using WindowsIncidentAnalyzer.Infrastructure;
using WindowsIncidentAnalyzer.Models;
using WindowsIncidentAnalyzer.Repositories;

namespace WindowsIncidentAnalyzer.Services;

public sealed class IocDetectionService(
    IEventRepository eventRepository,
    IIocRepository iocRepository,
    IOptions<AnalyzerOptions> options,
    ILogger<IocDetectionService> logger) : IIocDetectionService
{
    private static readonly HashSet<string> SupportedTypes = new(StringComparer.OrdinalIgnoreCase)
    {
        "ip", "ipv4", "ipv6", "domain", "hash", "sha256", "sha1", "md5", "filename", "file", "url", "user"
    };

    public async Task<IReadOnlyList<IocMatch>> ScanAsync(EventQueryFilter? filter, CancellationToken cancellationToken)
    {
        var iocs = await iocRepository.GetAllAsync(cancellationToken);
        if (iocs.Count == 0)
        {
            logger.LogInformation("No IOCs imported; scan skipped");
            return [];
        }

        var events = await eventRepository.QueryAsync(
            filter ?? new EventQueryFilter { Limit = 100000 },
            cancellationToken);
        return Scan(events, iocs);
    }

    public IReadOnlyList<IocMatch> Scan(IEnumerable<WindowsEvent> events, IEnumerable<Ioc> iocs)
    {
        var indicators = iocs
            .Where(i => !string.IsNullOrWhiteSpace(i.Value) && SupportedTypes.Contains(i.Type))
            .Select(i => new Ioc
            {
                Id = i.Id,
                Type = NormalizeType(i.Type),
                Value = i.Value.Trim(),
                Source = i.Source,
                Comment = i.Comment
            })
            .ToList();

        var eventList = events as IReadOnlyList<WindowsEvent> ?? events.ToList();
        var analysis = options.Value.Analysis;
        var matches = new ConcurrentBag<IocMatch>();

        if (analysis.EnableParallelAnalysis && eventList.Count > 1)
        {
            var parallelOptions = ParallelAnalysis.CreateCpuBoundOptions(analysis);
            Parallel.ForEach(eventList, parallelOptions, evt =>
            {
                ScanEvent(evt, indicators, matches);
            });
        }
        else
        {
            foreach (var evt in eventList)
            {
                ScanEvent(evt, indicators, matches);
            }
        }

        logger.LogInformation("IOC scan produced {Count} match(es) against {IocCount} indicator(s)", matches.Count, indicators.Count);
        return matches.ToList();
    }

    private static void ScanEvent(WindowsEvent evt, IReadOnlyList<Ioc> indicators, ConcurrentBag<IocMatch> matches)
    {
        foreach (var ioc in indicators)
        {
            if (TryMatch(evt, ioc, out var field))
            {
                matches.Add(new IocMatch
                {
                    IocType = ioc.Type,
                    IocValue = ioc.Value,
                    EventId = evt.EventId,
                    TimestampUtc = evt.TimeCreatedUtc,
                    Host = evt.ComputerName,
                    RelatedProcess = evt.ProcessName,
                    RelatedUser = evt.User ?? evt.TargetUserName,
                    MatchedField = field,
                    EventRowId = evt.Id
                });
            }
        }
    }

    public static bool TryMatch(WindowsEvent evt, Ioc ioc, out string field)
    {
        field = string.Empty;
        var value = ioc.Value;
        switch (NormalizeType(ioc.Type))
        {
            case "ip":
                if (Equals(evt.SourceIpAddress, value)) { field = "SourceIpAddress"; return true; }
                if (Equals(evt.DestinationIpAddress, value)) { field = "DestinationIpAddress"; return true; }
                if (Contains(evt.RawXml, value)) { field = "RawXml"; return true; }
                break;
            case "domain":
                if (Contains(evt.QueryName, value)) { field = "QueryName"; return true; }
                if (Contains(evt.CommandLine, value)) { field = "CommandLine"; return true; }
                if (Contains(evt.ScriptBlock, value)) { field = "ScriptBlock"; return true; }
                if (Contains(evt.RawXml, value)) { field = "RawXml"; return true; }
                break;
            case "hash":
                if (Contains(evt.Hashes, value)) { field = "Hashes"; return true; }
                if (Equals(evt.ScriptBlockHash, value)) { field = "ScriptBlockHash"; return true; }
                if (Contains(evt.CommandLine, value)) { field = "CommandLine"; return true; }
                if (Contains(evt.RawXml, value)) { field = "RawXml"; return true; }
                break;
            case "filename":
                if (Contains(evt.ProcessName, value)) { field = "ProcessName"; return true; }
                if (Contains(evt.ParentProcessName, value)) { field = "ParentProcessName"; return true; }
                if (Contains(evt.ProcessPath, value)) { field = "ProcessPath"; return true; }
                if (Contains(evt.CommandLine, value)) { field = "CommandLine"; return true; }
                if (Contains(evt.ScriptBlock, value)) { field = "ScriptBlock"; return true; }
                break;
            case "url":
                if (Contains(evt.CommandLine, value) || Contains(evt.ScriptBlock, value) || Contains(evt.RawXml, value))
                {
                    field = "CommandLine/ScriptBlock";
                    return true;
                }

                break;
            case "user":
                if (Contains(evt.User, value) || Contains(evt.TargetUserName, value))
                {
                    field = "User";
                    return true;
                }

                break;
        }

        return false;
    }

    public static string NormalizeType(string type) => type.Trim().ToLowerInvariant() switch
    {
        "ipv4" or "ipv6" or "ipaddress" => "ip",
        "sha256" or "sha1" or "md5" => "hash",
        "file" or "name" => "filename",
        var t => t
    };

    private static bool Equals(string? left, string right) =>
        !string.IsNullOrEmpty(left) && left.Equals(right, StringComparison.OrdinalIgnoreCase);

    private static bool Contains(string? haystack, string needle) =>
        !string.IsNullOrEmpty(haystack) && haystack.Contains(needle, StringComparison.OrdinalIgnoreCase);
}
