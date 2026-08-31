using System.Collections.Concurrent;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using WindowsIncidentAnalyzer.Configuration;
using WindowsIncidentAnalyzer.Detectors;
using WindowsIncidentAnalyzer.Infrastructure;
using WindowsIncidentAnalyzer.Models;
using WindowsIncidentAnalyzer.Repositories;

namespace WindowsIncidentAnalyzer.Services;

public sealed class SuspiciousActivityService(
    IEventRepository events,
    IEnumerable<IDetectionRule> detectors,
    IOptions<AnalyzerOptions> options,
    ILogger<SuspiciousActivityService> logger) : ISuspiciousActivityService
{
    private const string FullQueryCacheKey = "__all__";

    public async Task<IReadOnlyList<SecurityFinding>> AnalyzeAsync(EventQueryFilter? filter, CancellationToken cancellationToken)
    {
        var enabled = detectors.Where(d => d.IsEnabled).ToList();
        var analysis = options.Value.Analysis;
        logger.LogInformation(
            "Running {Count} enabled detection rules (parallel={Parallel}, workers={Workers})",
            enabled.Count,
            analysis.EnableParallelAnalysis,
            ParallelAnalysis.ResolveMaxDegreeOfParallelism(analysis));

        var cache = await LoadEventCacheAsync(enabled, filter, cancellationToken);
        List<SecurityFinding> findings;

        if (analysis.EnableParallelAnalysis && enabled.Count > 1)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var bag = new ConcurrentBag<SecurityFinding>();
            var parallelOptions = ParallelAnalysis.CreateCpuBoundOptions(analysis);
            Parallel.ForEach(enabled, parallelOptions, detector =>
            {
                foreach (var finding in RunDetector(detector, cache))
                {
                    bag.Add(finding);
                }
            });
            cancellationToken.ThrowIfCancellationRequested();
            findings = bag.ToList();
        }
        else
        {
            findings = [];
            foreach (var detector in enabled)
            {
                cancellationToken.ThrowIfCancellationRequested();
                findings.AddRange(RunDetector(detector, cache));
            }
        }

        return findings
            .OrderByDescending(f => f.Severity)
            .ThenBy(f => f.TimeUtc)
            .ToList();
    }

    private async Task<IReadOnlyDictionary<string, IReadOnlyList<WindowsEvent>>> LoadEventCacheAsync(
        IReadOnlyList<IDetectionRule> enabled,
        EventQueryFilter? filter,
        CancellationToken cancellationToken)
    {
        var cache = new Dictionary<string, IReadOnlyList<WindowsEvent>>();
        var idSets = new Dictionary<string, IReadOnlyList<int>>();
        var needsFullQuery = false;

        foreach (var detector in enabled)
        {
            if (detector.RelevantEventIds is { Count: > 0 } ids)
            {
                var key = BuildEventIdCacheKey(ids);
                idSets.TryAdd(key, ids);
            }
            else
            {
                needsFullQuery = true;
            }
        }

        foreach (var (key, ids) in idSets)
        {
            cache[key] = await events.GetByEventIdsAsync(ids, filter, cancellationToken);
        }

        if (needsFullQuery)
        {
            cache[FullQueryCacheKey] = await events.QueryAsync(
                filter ?? new EventQueryFilter { Limit = 100000 },
                cancellationToken);
        }

        return cache;
    }

    private static string BuildEventIdCacheKey(IEnumerable<int> ids) =>
        string.Join(",", ids.OrderBy(x => x));

    private static IReadOnlyList<WindowsEvent> ResolveSlice(
        IDetectionRule detector,
        IReadOnlyDictionary<string, IReadOnlyList<WindowsEvent>> cache)
    {
        if (detector.RelevantEventIds is { Count: > 0 } ids)
        {
            return cache[BuildEventIdCacheKey(ids)];
        }

        return cache[FullQueryCacheKey];
    }

    private List<SecurityFinding> RunDetector(
        IDetectionRule detector,
        IReadOnlyDictionary<string, IReadOnlyList<WindowsEvent>> cache)
    {
        var slice = ResolveSlice(detector, cache);
        try
        {
            var produced = detector.Analyze(slice).ToList();
            logger.LogInformation("Detector {Name} produced {Count} finding(s)", detector.Name, produced.Count);
            return produced;
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Detector {Name} failed; continuing with remaining rules", detector.Name);
            return [];
        }
    }
}
