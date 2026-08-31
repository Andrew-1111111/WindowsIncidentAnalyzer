using WindowsIncidentAnalyzer.Infrastructure;
using WindowsIncidentAnalyzer.Models;

namespace WindowsIncidentAnalyzer.Detectors;

public abstract class DetectorBase : IDetectionRule
{
    public abstract string Name { get; }

    public abstract string Description { get; }

    public abstract DetectionSeverity Severity { get; }

    public abstract bool IsEnabled { get; }

    public virtual IReadOnlyList<int>? RelevantEventIds => null;

    public abstract IEnumerable<SecurityFinding> Analyze(IEnumerable<WindowsEvent> events);

    protected static IEnumerable<WindowsEvent> OfEventId(IEnumerable<WindowsEvent> events, params int[] ids) =>
        events.Where(e => ids.Contains(e.EventId));

    protected static bool IsMachineAccount(WindowsEvent evt)
    {
        var targetSid = evt.GetProperty("TargetUserSid");
        if (!string.IsNullOrWhiteSpace(targetSid) && !WindowsLocale.IsNullSid(targetSid))
        {
            return WindowsLocale.IsBuiltInServiceSid(targetSid)
                   || WindowsLocale.IsBuiltInServiceAccountName(evt.TargetUserName);
        }

        return WindowsLocale.IsBuiltInServiceSid(evt.GetProperty("SubjectUserSid"))
               || WindowsLocale.IsBuiltInServiceAccountName(evt.TargetUserName)
               || WindowsLocale.IsBuiltInServiceAccountName(evt.User);
    }

    protected static bool IsMachineAccount(string? user) =>
        WindowsLocale.IsBuiltInServiceAccountName(user);

    protected static string AccountKey(WindowsEvent evt) =>
        $"{(evt.TargetDomainName ?? evt.Domain ?? string.Empty).ToLowerInvariant()}\\{(evt.TargetUserName ?? evt.User ?? string.Empty).ToLowerInvariant()}";

    protected static string IpKey(WindowsEvent evt) =>
        (evt.SourceIpAddress ?? string.Empty).Trim().ToLowerInvariant();

    protected SecurityFinding CreateFinding(
        string title,
        string description,
        DetectionSeverity severity,
        WindowsEvent? primary,
        IEnumerable<WindowsEvent>? related = null,
        string? details = null,
        Action<FindingContext>? configureContext = null)
    {
        var relatedList = related?.ToList() ?? [];
        if (primary != null && relatedList.All(e => e.Id != primary.Id))
        {
            relatedList.Insert(0, primary);
        }

        var sample = primary ?? relatedList.FirstOrDefault();
        var context = FindingContextMapper.FromEvent(sample);
        FindingContextMapper.ApplyRuleMetadata(context, Name, title, Name, severity);
        configureContext?.Invoke(context);
        WindowsEventCompatibility.ApplyEventClassification(context, sample);

        var severityValidation = WindowsEventCompatibility.ValidateSeverity(severity, sample, context, Name);
        var effectiveSeverity = severityValidation.Severity;
        if (!severityValidation.Matches && severity > effectiveSeverity)
        {
            context.RequestedSeverity = severity;
        }

        var finding = new SecurityFinding
        {
            RuleName = Name,
            Title = title,
            Description = description,
            Severity = effectiveSeverity,
            Details = details,
            RelatedEventRowIds = relatedList.Select(e => e.Id).Where(id => id > 0).Distinct().ToList()
        };

        FindingContextMapper.SyncLegacyFields(finding, context);
        context.Severity = effectiveSeverity;
        return finding;
    }
}
