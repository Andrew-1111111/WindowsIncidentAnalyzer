using System.Collections.Concurrent;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using WindowsIncidentAnalyzer.Configuration;
using WindowsIncidentAnalyzer.Infrastructure;
using WindowsIncidentAnalyzer.Models;
using WindowsIncidentAnalyzer.Repositories;

namespace WindowsIncidentAnalyzer.Services;

public sealed class CveDetectionService(
    IEventRepository eventRepository,
    ICveRepository cveRepository,
    IOptions<AnalyzerOptions> options,
    ILogger<CveDetectionService> logger) : ICveDetectionService
{
    private static readonly Regex CvePattern = new(
        @"\bCVE-\d{4}-\d{4,}\b",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled);

    public async Task<IReadOnlyList<CveMatch>> ScanAsync(EventQueryFilter? filter, CancellationToken cancellationToken)
    {
        var records = await cveRepository.GetAllAsync(cancellationToken);
        if (records.Count == 0)
        {
            logger.LogInformation("No CVE records loaded; scan skipped");
            return [];
        }

        var lookup = records.ToDictionary(r => r.CveId, StringComparer.OrdinalIgnoreCase);
        var events = await eventRepository.QueryAsync(
            filter ?? new EventQueryFilter { Limit = 100000 },
            cancellationToken);
        return Scan(events, lookup);
    }

    public IReadOnlyList<CveMatch> Scan(
        IEnumerable<WindowsEvent> events,
        IReadOnlyDictionary<string, CveRecord> lookup)
    {
        var eventList = events as IReadOnlyList<WindowsEvent> ?? events.ToList();
        var analyzer = options.Value;
        var matches = new ConcurrentBag<CveMatch>();

        if (ParallelAnalysis.ShouldUseParallel(analyzer, eventList.Count))
        {
            var parallelOptions = ParallelAnalysis.CreateCpuBoundOptions(analyzer);
            Parallel.ForEach(eventList, parallelOptions, evt => ScanEvent(evt, lookup, matches));
        }
        else
        {
            foreach (var evt in eventList)
            {
                ScanEvent(evt, lookup, matches);
            }
        }

        var result = matches
            .GroupBy(m => $"{m.EventRowId}:{m.CveId}", StringComparer.OrdinalIgnoreCase)
            .Select(g => g.First())
            .OrderBy(m => m.TimestampUtc)
            .ThenBy(m => m.CveId, StringComparer.OrdinalIgnoreCase)
            .ToList();

        logger.LogInformation("CVE scan produced {Count} match(es) against {CveCount} catalog record(s)", result.Count, lookup.Count);
        return result;
    }

    private static void ScanEvent(
        WindowsEvent evt,
        IReadOnlyDictionary<string, CveRecord> lookup,
        ConcurrentBag<CveMatch> matches)
    {
        foreach (var (field, text) in EnumerateSearchableFields(evt))
        {
            if (string.IsNullOrWhiteSpace(text))
            {
                continue;
            }

            foreach (Match match in CvePattern.Matches(text))
            {
                var cveId = match.Value.ToUpperInvariant();
                if (!lookup.TryGetValue(cveId, out var record))
                {
                    continue;
                }

                matches.Add(new CveMatch
                {
                    CveId = cveId,
                    VulnerabilityName = record.VulnerabilityName,
                    ShortDescription = record.ShortDescription,
                    VendorProject = record.VendorProject,
                    Product = record.Product,
                    KnownRansomwareUse = record.KnownRansomwareUse,
                    EventId = evt.EventId,
                    TimestampUtc = evt.TimeCreatedUtc,
                    Host = evt.ComputerName,
                    RelatedProcess = evt.ProcessName ?? evt.ProcessPath,
                    RelatedUser = evt.TargetUserName ?? evt.User,
                    MatchedField = field,
                    EventRowId = evt.Id
                });
            }
        }
    }

    private static IEnumerable<(string Field, string? Value)> EnumerateSearchableFields(WindowsEvent evt)
    {
        yield return ("CommandLine", evt.CommandLine);
        yield return ("ParentCommandLine", evt.ParentCommandLine);
        yield return ("ScriptBlock", evt.ScriptBlock);
        yield return ("RawXml", evt.RawXml);
        yield return ("PropertiesJson", evt.Properties.Count == 0 ? null : string.Join(' ', evt.Properties.Values));
        yield return ("ProcessPath", evt.ProcessPath);
        yield return ("TaskName", evt.TaskName);
        yield return ("ServiceName", evt.ServiceName);
        yield return ("QueryName", evt.QueryName);
    }
}
