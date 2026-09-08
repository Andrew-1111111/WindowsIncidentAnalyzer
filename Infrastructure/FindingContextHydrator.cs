using WindowsIncidentAnalyzer.Models;

namespace WindowsIncidentAnalyzer.Infrastructure;

/// <summary>
/// Fills empty finding context fields from the related Windows event (export / rehydrate).
/// </summary>
public static class FindingContextHydrator
{
    public static void FillGaps(SecurityFinding finding, WindowsEvent? evt)
    {
        if (evt == null)
        {
            return;
        }

        var gap = FindingContextMapper.FromEvent(evt);
        var ctx = finding.Context;

        ctx.TimestampUtc ??= gap.TimestampUtc;
        ctx.EventId ??= gap.EventId;
        ctx.EventRecordId ??= gap.EventRecordId;
        ctx.ProcessId ??= gap.ProcessId;
        ctx.ParentProcessId ??= gap.ParentProcessId;
        ctx.SourcePort ??= gap.SourcePort;
        ctx.DestinationPort ??= gap.DestinationPort;

        ctx.Provider = Coalesce(ctx.Provider, gap.Provider);
        ctx.Channel = Coalesce(ctx.Channel, gap.Channel);
        ctx.Host = Coalesce(ctx.Host, gap.Host);
        ctx.Domain = Coalesce(ctx.Domain, gap.Domain);
        ctx.User = Coalesce(ctx.User, gap.User);
        ctx.UserSid = Coalesce(ctx.UserSid, gap.UserSid);
        ctx.LogonId = Coalesce(ctx.LogonId, gap.LogonId);
        ctx.ProcessName = Coalesce(ctx.ProcessName, gap.ProcessName);
        ctx.Image = Coalesce(ctx.Image, gap.Image);
        ctx.CommandLine = Coalesce(ctx.CommandLine, gap.CommandLine);
        ctx.ParentImage = Coalesce(ctx.ParentImage, gap.ParentImage);
        ctx.ParentCommandLine = Coalesce(ctx.ParentCommandLine, gap.ParentCommandLine);
        ctx.WorkingDirectory = Coalesce(ctx.WorkingDirectory, gap.WorkingDirectory);
        ctx.IntegrityLevel = Coalesce(ctx.IntegrityLevel, gap.IntegrityLevel);
        ctx.ElevationType = Coalesce(ctx.ElevationType, gap.ElevationType);
        ctx.FilePath = Coalesce(ctx.FilePath, gap.FilePath);
        ctx.Sha256 = Coalesce(ctx.Sha256, gap.Sha256);
        ctx.Md5 = Coalesce(ctx.Md5, gap.Md5);
        ctx.Signer = Coalesce(ctx.Signer, gap.Signer);
        ctx.OriginalFileName = Coalesce(ctx.OriginalFileName, gap.OriginalFileName);
        ctx.SourceIp = Coalesce(ctx.SourceIp, gap.SourceIp);
        ctx.DestinationIp = Coalesce(ctx.DestinationIp, gap.DestinationIp);
        ctx.RawXml = Coalesce(ctx.RawXml, gap.RawXml);
        ctx.RawEvent = Coalesce(ctx.RawEvent, gap.RawEvent);
        ctx.EventType = Coalesce(ctx.EventType, gap.EventType);
        ctx.CategoryMatchesEvent ??= gap.CategoryMatchesEvent;
        ctx.SeverityMatchesEvent ??= gap.SeverityMatchesEvent;

        FindingContextMapper.SyncLegacyFields(finding, ctx);
    }

    public static void FillGaps(
        IEnumerable<SecurityFinding> findings,
        IReadOnlyDictionary<long, WindowsEvent> events)
    {
        foreach (var finding in findings)
        {
            var rowId = finding.RelatedEventRowIds.FirstOrDefault();
            if (rowId > 0 && events.TryGetValue(rowId, out var evt))
            {
                FillGaps(finding, evt);
            }
        }
    }

    private static string? Coalesce(string? preferred, string? fallback) =>
        string.IsNullOrWhiteSpace(preferred) ? fallback : preferred;
}
