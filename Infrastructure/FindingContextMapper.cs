using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;
using WindowsIncidentAnalyzer.Models;

namespace WindowsIncidentAnalyzer.Infrastructure;

public static class FindingContextMapper
{
    private static readonly JsonSerializerOptions RawEventOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        WriteIndented = false
    };

    public static FindingContext FromEvent(WindowsEvent? evt)
    {
        var context = new FindingContext();
        if (evt == null)
        {
            return context;
        }

        context.TimestampUtc = evt.TimeCreatedUtc;
        context.EventId = evt.EventId > 0 ? evt.EventId : null;
        context.EventRecordId = evt.EventRecordId;
        context.Provider = evt.ProviderName;
        context.Channel = evt.LogName;
        context.Host = evt.ComputerName;
        context.Domain = evt.TargetDomainName ?? evt.Domain;
        context.User = evt.TargetUserName ?? evt.User;
        context.UserSid = FirstNonEmpty(
            evt.GetProperty("TargetUserSid"),
            evt.GetProperty("SubjectUserSid"),
            evt.GetProperty("SecurityUserId"));
        context.LogonId = FirstNonEmpty(
            evt.GetProperty("TargetLogonId"),
            evt.GetProperty("SubjectLogonId"));
        context.ProcessId = evt.ProcessId;
        context.ParentProcessId = evt.ParentProcessId;
        context.ProcessName = evt.ProcessName;
        context.Image = evt.ProcessPath ?? evt.ProcessName;
        context.CommandLine = evt.CommandLine;
        context.ParentImage = FirstNonEmpty(evt.GetProperty("ParentImage"), evt.ParentProcessName);
        context.ParentCommandLine = evt.ParentCommandLine;
        context.WorkingDirectory = evt.GetProperty("CurrentDirectory");
        context.IntegrityLevel = evt.GetProperty("IntegrityLevel");
        context.ElevationType = FirstNonEmpty(
            evt.GetProperty("ElevatedToken"),
            evt.GetProperty("ElevationType"));
        context.FilePath = FirstNonEmpty(
            evt.GetProperty("TargetFilename"),
            evt.ProcessPath,
            evt.GetProperty("ObjectName"),
            evt.GetProperty("Image"));
        context.OriginalFileName = evt.GetProperty("OriginalFileName");
        context.Signer = FirstNonEmpty(evt.GetProperty("Signature"), evt.GetProperty("Signer"));
        ParseHashes(evt.Hashes, context);
        context.SourceIp = evt.SourceIpAddress;
        context.SourcePort = evt.SourcePort;
        context.DestinationIp = evt.DestinationIpAddress;
        context.DestinationPort = evt.DestinationPort;
        context.RawXml = evt.RawXml;
        context.RawEvent = BuildRawEventJson(evt);
        WindowsEventCompatibility.ApplyEventClassification(context, evt);
        return context;
    }

    public static void ApplyRuleMetadata(
        FindingContext context,
        string ruleId,
        string ruleTitle,
        string category,
        DetectionSeverity severity)
    {
        context.RuleId = ruleId;
        context.RuleTitle = ruleTitle;
        context.Category = category;
        context.Severity = severity;
    }

    public static void SyncLegacyFields(SecurityFinding finding, FindingContext context)
    {
        finding.Context = context;
        finding.TimeUtc = context.TimestampUtc ?? finding.TimeUtc;
        finding.ComputerName = context.Host ?? finding.ComputerName;
        finding.User = context.User ?? finding.User;
        finding.SourceIpAddress = context.SourceIp ?? finding.SourceIpAddress;
        finding.ProcessName = context.ProcessName ?? context.Image ?? finding.ProcessName;
    }

    private static string? BuildRawEventJson(WindowsEvent evt)
    {
        try
        {
            return JsonSerializer.Serialize(new
            {
                evt.Id,
                evt.ComputerName,
                evt.LogName,
                evt.ProviderName,
                evt.EventId,
                evt.EventRecordId,
                timeCreatedUtc = evt.TimeCreatedUtc.ToString("o", CultureInfo.InvariantCulture),
                evt.Level,
                evt.User,
                evt.Domain,
                evt.TargetUserName,
                evt.TargetDomainName,
                evt.ProcessName,
                evt.ProcessPath,
                evt.ProcessId,
                evt.ParentProcessName,
                evt.ParentProcessId,
                evt.CommandLine,
                evt.ParentCommandLine,
                evt.SourceIpAddress,
                evt.DestinationIpAddress,
                evt.SourcePort,
                evt.DestinationPort,
                evt.WorkstationName,
                evt.Hashes,
                evt.ScriptBlock,
                evt.QueryName,
                evt.TaskName,
                evt.ServiceName,
                evt.LogonType,
                properties = evt.Properties
            }, RawEventOptions);
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private static void ParseHashes(string? hashes, FindingContext context)
    {
        if (string.IsNullOrWhiteSpace(hashes))
        {
            return;
        }

        foreach (var part in hashes.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries))
        {
            var separator = part.IndexOf('=');
            if (separator <= 0)
            {
                continue;
            }

            var algorithm = part[..separator].Trim();
            var value = part[(separator + 1)..].Trim();
            if (algorithm.Equals("SHA256", StringComparison.OrdinalIgnoreCase))
            {
                context.Sha256 = value;
            }
            else if (algorithm.Equals("MD5", StringComparison.OrdinalIgnoreCase))
            {
                context.Md5 = value;
            }
        }
    }

    private static string? FirstNonEmpty(params string?[] values)
    {
        foreach (var value in values)
        {
            if (!string.IsNullOrWhiteSpace(value))
            {
                return value;
            }
        }

        return null;
    }
}
