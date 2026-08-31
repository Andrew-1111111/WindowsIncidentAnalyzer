using WindowsIncidentAnalyzer.Infrastructure;
using WindowsIncidentAnalyzer.Models;

namespace WindowsIncidentAnalyzer.Detectors;

public sealed record DetectionSignature(
    string Id,
    string Title,
    string Description,
    DetectionSeverity Severity,
    IReadOnlyList<int>? EventIds = null,
    IReadOnlyList<string>? ProcessNames = null,
    IReadOnlyList<string>? Any = null,
    IReadOnlyList<string>? All = null,
    IReadOnlyList<string>? Exclude = null,
    string? Provider = null);

public abstract class SignatureRuleBase : DetectorBase
{
    protected abstract IReadOnlyList<DetectionSignature> Signatures { get; }

    public override IReadOnlyList<int>? RelevantEventIds =>
        Signatures
            .SelectMany(s => s.EventIds ?? [])
            .Distinct()
            .OrderBy(id => id)
            .ToArray();

    public override IEnumerable<SecurityFinding> Analyze(IEnumerable<WindowsEvent> events)
    {
        if (!IsEnabled)
        {
            yield break;
        }

        foreach (var evt in events)
        {
            var blob = BuildBlob(evt);
            foreach (var signature in Signatures)
            {
                if (!Matches(evt, blob, signature))
                {
                    continue;
                }

                yield return CreateFinding(
                    signature.Title,
                    signature.Description,
                    signature.Severity,
                    evt,
                    details: $"signature={signature.Id}; eventId={evt.EventId}; process={evt.ProcessName}; commandLine={Trim(evt.CommandLine, 500)}",
                    configureContext: ctx => ctx.RuleId = signature.Id);
            }
        }
    }

    private static bool Matches(WindowsEvent evt, string blob, DetectionSignature signature)
    {
        if (!WindowsEventCompatibility.MatchesDeclaredEventIds(evt, signature.EventIds))
        {
            return false;
        }

        if (!string.IsNullOrWhiteSpace(signature.Provider) &&
            !(evt.ProviderName?.Contains(signature.Provider, StringComparison.OrdinalIgnoreCase) ?? false))
        {
            return false;
        }

        if (signature.ProcessNames is { Count: > 0 } processes &&
            !processes.Any(name => ProcessMatches(evt, name)))
        {
            return false;
        }

        if (signature.Any is { Count: > 0 } any &&
            !any.Any(token => blob.Contains(token, StringComparison.OrdinalIgnoreCase)))
        {
            return false;
        }

        if (signature.All is { Count: > 0 } all &&
            !all.All(token => blob.Contains(token, StringComparison.OrdinalIgnoreCase)))
        {
            return false;
        }

        return signature.Exclude is not { Count: > 0 } excluded ||
               !excluded.Any(token => blob.Contains(token, StringComparison.OrdinalIgnoreCase));
    }

    private static bool ProcessMatches(WindowsEvent evt, string expected)
    {
        var names = new[] { evt.ProcessName, evt.ProcessPath };
        return names.Any(value =>
            !string.IsNullOrWhiteSpace(value) &&
            (value.Equals(expected, StringComparison.OrdinalIgnoreCase) ||
             value.EndsWith("\\" + expected, StringComparison.OrdinalIgnoreCase)));
    }

    private static string BuildBlob(WindowsEvent evt)
    {
        var values = new List<string?>
        {
            evt.ProcessName,
            evt.ProcessPath,
            evt.ParentProcessName,
            evt.CommandLine,
            evt.ParentCommandLine,
            evt.ScriptBlock,
            evt.ServiceName,
            evt.TaskName,
            evt.QueryName,
            evt.Hashes,
            evt.RawXml
        };
        values.AddRange(evt.Properties.SelectMany(pair => new[] { pair.Key, pair.Value }));
        return string.Join('\n', values.Where(value => !string.IsNullOrWhiteSpace(value)));
    }

    private static string? Trim(string? value, int max) =>
        string.IsNullOrEmpty(value) || value.Length <= max ? value : value[..max] + "...";
}
